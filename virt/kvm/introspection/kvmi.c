// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection
 *
 * Copyright (C) 2017-2020 Bitdefender S.R.L.
 *
 */
#include <linux/mmu_context.h>
#include "kvmi_int.h"
#include <linux/kthread.h>
#define CREATE_TRACE_POINTS
#include <trace/events/kvmi.h>

#define MAX_PAUSE_REQUESTS 1001

static bool kvmi_track_preread(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
			       u8 *new, int bytes, bool *data_ready,
			       struct kvm_page_track_notifier_node *node);
static bool kvmi_track_prewrite(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
				const u8 *new, int bytes,
				struct kvm_page_track_notifier_node *node);
static bool kvmi_track_preexec(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
			       struct kvm_page_track_notifier_node *node);
static void kvmi_track_create_slot(struct kvm *kvm,
				   struct kvm_memory_slot *slot,
				   unsigned long npages,
				   struct kvm_page_track_notifier_node *node);
static void kvmi_track_flush_slot(struct kvm *kvm, struct kvm_memory_slot *slot,
				  struct kvm_page_track_notifier_node *node);
static void kvmi_create_vcpu_event(struct kvm_vcpu *vcpu);
static int kvmi_get_gfn_access(struct kvm_introspection *kvmi, const gfn_t gfn,
			       u8 *access, u32 *write_bitmap, u16 view);
static u8 kvmi_get_gfn_access_from_slot(struct kvm_memory_slot *slot,
					gfn_t gfn, u16 view,
					u32 *write_bitmap);

static struct kmem_cache *msg_cache;
static struct kmem_cache *job_cache;
static struct kmem_cache *radix_cache;

static const u8 rwx_access = KVMI_PAGE_ACCESS_R |
			     KVMI_PAGE_ACCESS_W |
			     KVMI_PAGE_ACCESS_X;
static const u8 full_access = KVMI_PAGE_ACCESS_R |
			     KVMI_PAGE_ACCESS_W |
			     KVMI_PAGE_ACCESS_X | KVMI_PAGE_SVE;
static const u32 default_write_bitmap;

void *kvmi_msg_alloc(void)
{
	return kmem_cache_zalloc(msg_cache, GFP_KERNEL);
}

void *kvmi_msg_alloc_check(size_t size)
{
	if (size > KVMI_MSG_SIZE_ALLOC)
		return NULL;
	return kvmi_msg_alloc();
}

void kvmi_msg_free(void *addr)
{
	if (addr)
		kmem_cache_free(msg_cache, addr);
}

static void kvmi_cache_destroy(void)
{
	kmem_cache_destroy(msg_cache);
	msg_cache = NULL;
	kmem_cache_destroy(job_cache);
	job_cache = NULL;
	kmem_cache_destroy(radix_cache);
	radix_cache = NULL;
}

static int kvmi_cache_create(void)
{
	msg_cache = kmem_cache_create("kvmi_msg", KVMI_MSG_SIZE_ALLOC,
				      4096, SLAB_ACCOUNT, NULL);
	job_cache = kmem_cache_create("kvmi_job",
				      sizeof(struct kvmi_job),
				      0, SLAB_ACCOUNT, NULL);
	radix_cache = kmem_cache_create("kvmi_radix_tree",
					sizeof(struct kvmi_mem_access),
					0, SLAB_ACCOUNT, NULL);

	if (!msg_cache || !job_cache || !radix_cache) {
		kvmi_cache_destroy();

		return -1;
	}

	return 0;
}

int kvmi_init(void)
{
	kvmi_mem_init();
	return kvmi_cache_create();
}

void kvmi_uninit(void)
{
	kvmi_mem_exit();
	kvmi_cache_destroy();
}

static void kvmi_make_request(struct kvm_vcpu *vcpu, bool wait)
{
	kvm_make_request(KVM_REQ_INTROSPECTION, vcpu);

	if (wait)
		kvm_vcpu_kick_and_wait(vcpu);
	else
		kvm_vcpu_kick(vcpu);
}

static int __kvmi_add_job(struct kvm_vcpu *vcpu,
			  void (*fct)(struct kvm_vcpu *vcpu, void *ctx),
			  void *ctx, void (*free_fct)(void *ctx))
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	struct kvmi_job *job;

	job = kmem_cache_zalloc(job_cache, GFP_KERNEL);
	if (unlikely(!job))
		return -ENOMEM;

	INIT_LIST_HEAD(&job->link);
	job->fct = fct;
	job->ctx = ctx;
	job->free_fct = free_fct;

	spin_lock(&vcpui->job_lock);
	list_add_tail(&job->link, &vcpui->job_list);
	spin_unlock(&vcpui->job_lock);

	return 0;
}

int kvmi_add_job(struct kvm_vcpu *vcpu,
		 void (*fct)(struct kvm_vcpu *vcpu, void *ctx),
		 void *ctx, void (*free_fct)(void *ctx))
{
	int err;

	err = __kvmi_add_job(vcpu, fct, ctx, free_fct);

	if (!err)
		kvmi_make_request(vcpu, false);

	return err;
}

static void kvmi_free_job(struct kvmi_job *job)
{
	if (job->free_fct)
		job->free_fct(job->ctx);

	kmem_cache_free(job_cache, job);
}

static bool alloc_vcpui(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_introspection *vcpui;

	vcpui = kzalloc(sizeof(*vcpui), GFP_KERNEL);
	if (!vcpui)
		return false;

	INIT_LIST_HEAD(&vcpui->job_list);
	spin_lock_init(&vcpui->job_lock);

	vcpu->kvmi = vcpui;

	return kvmi_arch_vcpu_alloc(vcpu);
}

static void kvmi_job_create_vcpu(struct kvm_vcpu *vcpu, void *ctx)
{
	if (is_vm_event_enabled(KVMI(vcpu->kvm), KVMI_EVENT_CREATE_VCPU))
		kvmi_create_vcpu_event(vcpu);
}

static int create_vcpui(struct kvm_vcpu *vcpu)
{
	if (!alloc_vcpui(vcpu))
		return -ENOMEM;

	if (kvmi_add_job(vcpu, kvmi_job_create_vcpu, NULL, NULL))
		return -ENOMEM;

	return 0;
}

static void free_vcpui(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_introspection *vcpui = vcpu->kvmi;
	struct kvmi_job *cur, *next;

	if (!vcpui)
		return;

	spin_lock(&vcpui->job_lock);
	list_for_each_entry_safe(cur, next, &vcpui->job_list, link) {
		list_del(&cur->link);
		kvmi_free_job(cur);
	}
	spin_unlock(&vcpui->job_lock);

	kfree(vcpui);
	vcpu->kvmi = NULL;

	kvmi_arch_request_restore_interception(vcpu);
	kvmi_make_request(vcpu, false);
}

static void kvmi_clear_mem_access(struct kvm *kvm)
{
	struct kvm_introspection *kvmi = KVMI(kvm);
	struct radix_tree_iter iter;
	void **slot;
	struct kvm_memory_slot *memslot;
	struct kvm_memslots *slots;
	int idx, view;
	u32 skip_mask = KVM_MEM_READONLY | KVM_MEMSLOT_INVALID;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);

	/* Clear any leftover in radix tree */
	for (view = 0; view < KVM_MAX_EPT_VIEWS; view++)
		radix_tree_for_each_slot(slot, &kvmi->access_tree[view],
					 &iter, 0) {
			struct kvmi_mem_access *m = *slot;

			radix_tree_iter_delete(&kvmi->access_tree[view],
					       &iter, slot);
			kmem_cache_free(radix_cache, m);
		}

	/* Remove restrictions */
	slots = kvm_memslots(kvm);
	kvm_for_each_memslot(memslot, slots)
		if (memslot->id < KVM_USER_MEM_SLOTS &&
				(memslot->flags & skip_mask) == 0) {
			gfn_t start = memslot->base_gfn;
			gfn_t gfn, end = start + memslot->npages;

			for (gfn = start; gfn < end; gfn++) {
				for (view = 0;
					view < KVM_MAX_EPT_VIEWS;
					view++) {
					kvmi_arch_update_page_tracking(kvm,
							memslot,
							gfn,
							full_access,
							full_access,
							view);
				}
				kvmi_arch_set_subpage_access(kvm, memslot,
						gfn,
						~default_write_bitmap);
			}
		}

	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);
}

static void free_kvmi(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	int i;

	kvmi_clear_mem_access(kvm);
	kvmi_clear_vm_tokens(kvm);

	refcount_set(&kvm->arch.kvmi_refcount,
			atomic_read(&kvm->online_vcpus));

	kvm_for_each_vcpu(i, vcpu, kvm)
		free_vcpui(vcpu);

	kfree(kvm->kvmi);
	kvm->kvmi = NULL;
}

int kvmi_vcpu_init(struct kvm_vcpu *vcpu)
{
	struct kvm_introspection *kvmi;
	int r = 0;

	mutex_lock(&vcpu->kvm->kvmi_lock);

	kvmi = kvmi_get(vcpu->kvm);
	if (!kvmi)
		goto out;

	r = create_vcpui(vcpu);

	kvmi_put(vcpu->kvm);
out:
	mutex_unlock(&vcpu->kvm->kvmi_lock);
	return r;
}

void kvmi_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	mutex_lock(&vcpu->kvm->kvmi_lock);
	free_vcpui(vcpu);
	kvmi_arch_vcpu_free(vcpu);
	mutex_unlock(&vcpu->kvm->kvmi_lock);
}

static struct kvm_introspection *
alloc_kvmi(struct kvm *kvm, const struct kvm_introspection_hook *hook)
{
	struct kvm_introspection *kvmi;
	struct kvm_vcpu *vcpu;
	int i;

	kvmi = kzalloc(sizeof(*kvmi), GFP_KERNEL);
	if (!kvmi)
		return NULL;

	BUILD_BUG_ON(sizeof(hook->uuid) != sizeof(kvmi->uuid));
	memcpy(&kvmi->uuid, &hook->uuid, sizeof(kvmi->uuid));

	set_bit(KVMI_GET_VERSION, kvmi->cmd_allow_mask);
	set_bit(KVMI_VM_CHECK_COMMAND, kvmi->cmd_allow_mask);
	set_bit(KVMI_VM_CHECK_EVENT, kvmi->cmd_allow_mask);

	atomic_set(&kvmi->ev_seq, 0);

	for (i = 0; i < ARRAY_SIZE(kvmi->access_tree); i++)
		INIT_RADIX_TREE(&kvmi->access_tree[i],
				GFP_KERNEL & ~__GFP_DIRECT_RECLAIM);
	rwlock_init(&kvmi->access_tree_lock);

	kvmi->arch.kptn_node.track_preread = kvmi_track_preread;
	kvmi->arch.kptn_node.track_prewrite = kvmi_track_prewrite;
	kvmi->arch.kptn_node.track_preexec = kvmi_track_preexec;
	kvmi->arch.kptn_node.track_create_slot = kvmi_track_create_slot;
	kvmi->arch.kptn_node.track_flush_slot = kvmi_track_flush_slot;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		int err = create_vcpui(vcpu);

		if (err) {
			free_kvmi(kvm);
			return NULL;
		}
	}

	kvmi->kvm = kvm;

	return kvmi;
}

static void kvmi_destroy(struct kvm_introspection *kvmi)
{
	struct kvm *kvm = kvmi->kvm;

	free_kvmi(kvm);
}

static void kvmi_stop_recv_thread(struct kvm_introspection *kvmi)
{
	kvmi_sock_shutdown(kvmi);
}

static void __kvmi_unhook(struct kvm *kvm)
{
	struct kvm_introspection *kvmi = KVMI(kvm);

	wait_for_completion_killable(&kvm->kvmi_complete);

	kvm_page_track_unregister_notifier(kvm, &kvmi->arch.kptn_node);
	kvmi_sock_put(kvmi);
}

static void kvmi_unhook(struct kvm *kvm)
{
	struct kvm_introspection *kvmi;

	mutex_lock(&kvm->kvmi_lock);

	kvmi = KVMI(kvm);
	if (kvmi) {
		kvmi_stop_recv_thread(kvmi);
		__kvmi_unhook(kvm);
		kvmi_destroy(kvmi);
	}

	mutex_unlock(&kvm->kvmi_lock);
}

int kvmi_ioctl_unhook(struct kvm *kvm)
{
	kvmi_unhook(kvm);
	return 0;
}

struct kvm_introspection * __must_check kvmi_get(struct kvm *kvm)
{
	if (refcount_inc_not_zero(&kvm->kvmi_ref))
		return kvm->kvmi;

	return NULL;
}

void kvmi_put(struct kvm *kvm)
{
	if (refcount_dec_and_test(&kvm->kvmi_ref))
		complete(&kvm->kvmi_complete);
}

static int __kvmi_hook(struct kvm *kvm,
		       const struct kvm_introspection_hook *hook)
{
	struct kvm_introspection *kvmi = KVMI(kvm);

	if (!kvmi_sock_get(kvmi, hook->fd))
		return -EINVAL;

	kvm_page_track_register_notifier(kvm, &kvmi->arch.kptn_node);

	return 0;
}

static void kvmi_job_release_vcpu(struct kvm_vcpu *vcpu, void *ctx)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);

	atomic_set(&vcpui->pause_requests, 0);
	vcpui->waiting_for_reply = false;

	if (vcpui->singlestep.loop) {
		kvmi_arch_stop_singlestep(vcpu);
		vcpui->singlestep.loop = false;
	}
}

static void kvmi_release_vcpus(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	int i;

	kvm_for_each_vcpu(i, vcpu, kvm)
		kvmi_add_job(vcpu, kvmi_job_release_vcpu, NULL, NULL);
}

static int kvmi_recv_thread(void *arg)
{
	struct kvm_introspection *kvmi = arg;

	kvmi_info(kvmi, "Hooking VM\n");

	while (kvmi_msg_process(kvmi))
		;

	kvmi_info(kvmi, "Unhooking VM\n");

	/*
	 * Signal userspace (which might wait for POLLHUP only)
	 * and prevent the vCPUs from sending other events.
	 */
	kvmi_sock_shutdown(kvmi);

	kvmi_release_vcpus(kvmi->kvm);

	kvmi_put(kvmi->kvm);
	return 0;
}

static bool ready_to_hook(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	int i;

	if (kvm->kvmi)
		return false;

	kvm_for_each_vcpu(i, vcpu, kvm)
		if (kvmi_arch_vcpu_introspected(vcpu))
			return false;

	return true;
}

int kvmi_hook(struct kvm *kvm, const struct kvm_introspection_hook *hook)
{
	struct kvm_introspection *kvmi;
	int err = 0;

	mutex_lock(&kvm->kvmi_lock);

	if (!ready_to_hook(kvm)) {
		err = -EEXIST;
		goto out;
	}

	kvmi = alloc_kvmi(kvm, hook);
	if (!kvmi) {
		err = -ENOMEM;
		goto out;
	}

	kvm->kvmi = kvmi;

	err = __kvmi_hook(kvm, hook);
	if (err)
		goto destroy;

	init_completion(&kvm->kvmi_complete);

	refcount_set(&kvm->kvmi_ref, 1);
	/*
	 * Paired with refcount_inc_not_zero() from kvmi_get().
	 */
	smp_wmb();

	kvmi->recv = kthread_run(kvmi_recv_thread, kvmi, "kvmi-recv");
	if (IS_ERR(kvmi->recv)) {
		err = -ENOMEM;
		kvmi_put(kvm);
		goto unhook;
	}

	goto out;

unhook:
	__kvmi_unhook(kvm);
destroy:
	kvmi_destroy(kvmi);
out:
	mutex_unlock(&kvm->kvmi_lock);
	return err;
}

int kvmi_ioctl_hook(struct kvm *kvm, void __user *argp)
{
	struct kvm_introspection_hook i;

	if (copy_from_user(&i, argp, sizeof(i)))
		return -EFAULT;

	if (i.padding)
		return -EINVAL;

	return kvmi_hook(kvm, &i);
}

void kvmi_create_vm(struct kvm *kvm)
{
	mutex_init(&kvm->kvmi_lock);
}

void kvmi_destroy_vm(struct kvm *kvm)
{
	kvmi_unhook(kvm);
}

static int kvmi_ioctl_get_feature(void __user *argp, bool *allow, int *id,
				  unsigned long *bitmask)
{
	struct kvm_introspection_feature feat;
	int all_bits = -1;

	if (copy_from_user(&feat, argp, sizeof(feat)))
		return -EFAULT;

	if (feat.id < 0 && feat.id != all_bits)
		return -EINVAL;

	*allow = !!(feat.allow & 1);
	*id = feat.id;
	*bitmask = *id == all_bits ? -1 : BIT(feat.id);

	return 0;
}

static int kvmi_ioctl_feature(struct kvm *kvm,
			      bool allow, unsigned long *requested,
			      size_t off_dest, unsigned int nbits)
{
	struct kvm_introspection *kvmi;
	unsigned long *dest;
	int err = 0;

	mutex_lock(&kvm->kvmi_lock);

	kvmi = KVMI(kvm);
	if (!kvmi) {
		err = -EFAULT;
		goto out;
	}

	dest = (unsigned long *)((char *)kvmi + off_dest);

	if (allow)
		bitmap_or(dest, dest, requested, nbits);
	else
		bitmap_andnot(dest, dest, requested, nbits);

out:
	mutex_unlock(&kvm->kvmi_lock);

	return err;
}

int kvmi_ioctl_event(struct kvm *kvm, void __user *argp)
{
	DECLARE_BITMAP(requested, KVMI_NUM_EVENTS);
	DECLARE_BITMAP(known, KVMI_NUM_EVENTS);
	size_t off_bitmap;
	bool allow;
	int err;
	int id;

	err = kvmi_ioctl_get_feature(argp, &allow, &id, requested);
	if (err)
		return err;

	bitmap_from_u64(known, KVMI_KNOWN_EVENTS);
	bitmap_and(requested, requested, known, KVMI_NUM_EVENTS);

	off_bitmap = offsetof(struct kvm_introspection, event_allow_mask);

	return kvmi_ioctl_feature(kvm, allow, requested, off_bitmap,
				  KVMI_NUM_EVENTS);
}

int kvmi_ioctl_command(struct kvm *kvm, void __user *argp)
{
	DECLARE_BITMAP(requested, KVMI_NUM_COMMANDS);
	DECLARE_BITMAP(known, KVMI_NUM_COMMANDS);
	size_t off_bitmap;
	bool allow;
	int err;
	int id;

	err = kvmi_ioctl_get_feature(argp, &allow, &id, requested);
	if (err)
		return err;

	bitmap_from_u64(known, KVMI_KNOWN_COMMANDS);
	bitmap_and(requested, requested, known, KVMI_NUM_COMMANDS);

	if (!allow) {
		DECLARE_BITMAP(always_allowed, KVMI_NUM_COMMANDS);

		if (id == KVMI_GET_VERSION
				|| id == KVMI_VM_CHECK_COMMAND
				|| id == KVMI_VM_CHECK_EVENT)
			return -EPERM;

		set_bit(KVMI_GET_VERSION, always_allowed);
		set_bit(KVMI_VM_CHECK_COMMAND, always_allowed);
		set_bit(KVMI_VM_CHECK_EVENT, always_allowed);

		bitmap_andnot(requested, requested, always_allowed,
			      KVMI_NUM_COMMANDS);
	}

	off_bitmap = offsetof(struct kvm_introspection, cmd_allow_mask);

	return kvmi_ioctl_feature(kvm, allow, requested, off_bitmap,
				  KVMI_NUM_COMMANDS);
}

static bool kvmi_unhook_event(struct kvm_introspection *kvmi)
{
	int err;

	if (!is_vm_event_enabled(kvmi, KVMI_EVENT_UNHOOK))
		return false;

	err = kvmi_msg_send_unhook(kvmi);

	return !err;
}

int kvmi_ioctl_preunhook(struct kvm *kvm)
{
	struct kvm_introspection *kvmi;
	int err = 0;

	mutex_lock(&kvm->kvmi_lock);

	kvmi = KVMI(kvm);
	if (!kvmi) {
		err = -EFAULT;
		goto out;
	}

	if (!kvmi_unhook_event(kvmi))
		err = -ENOENT;

out:
	mutex_unlock(&kvm->kvmi_lock);

	return err;
}

int kvmi_cmd_vm_control_events(struct kvm_introspection *kvmi,
				unsigned int event_id, bool enable)
{
	if (enable)
		set_bit(event_id, kvmi->vm_event_enable_mask);
	else
		clear_bit(event_id, kvmi->vm_event_enable_mask);

	return 0;
}

int kvmi_cmd_vcpu_control_events(struct kvm_vcpu *vcpu,
				 unsigned int event_id, bool enable)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);

	if (enable)
		set_bit(event_id, vcpui->ev_mask);
	else
		clear_bit(event_id, vcpui->ev_mask);

	return kvmi_arch_cmd_control_intercept(vcpu, event_id, enable);
}

static long
get_user_pages_remote_unlocked(struct mm_struct *mm, unsigned long start,
				unsigned long nr_pages, unsigned int gup_flags,
				struct page **pages)
{
	struct vm_area_struct **vmas = NULL;
	struct task_struct *tsk = NULL;
	int locked = 1;
	long r;

	down_read(&mm->mmap_sem);
	r = get_user_pages_remote(tsk, mm, start, nr_pages, gup_flags,
				  pages, vmas, &locked);
	if (locked)
		up_read(&mm->mmap_sem);

	return r;
}

static void *get_page_ptr(struct kvm *kvm, gpa_t gpa, struct page **page,
			  bool write)
{
	unsigned int flags = write ? FOLL_WRITE : 0;
	unsigned long hva;

	*page = NULL;

	hva = gfn_to_hva(kvm, gpa_to_gfn(gpa));

	if (kvm_is_error_hva(hva))
		return NULL;

	if (get_user_pages_remote_unlocked(kvm->mm, hva, 1, flags, page) != 1)
		return NULL;

	return write ? kmap_atomic(*page) : kmap(*page);
}

static void put_page_ptr(void *ptr, struct page *page, bool write)
{
	if (ptr) {
		if (write)
			kunmap_atomic(ptr);
		else
			kunmap(ptr);
	}
	if (page)
		put_page(page);
}

int kvmi_cmd_read_physical(struct kvm *kvm, u64 gpa, u64 size,
			   int (*send)(struct kvm_introspection *,
					const struct kvmi_msg_hdr *,
					int err, const void *buf, size_t),
			   const struct kvmi_msg_hdr *ctx)
{
	void *ptr_page = NULL, *ptr = NULL;
	struct page *page = NULL;
	size_t ptr_size = 0;
	int srcu_idx;
	int err, ec = 0;

	srcu_idx = srcu_read_lock(&kvm->srcu);

	ptr_page = get_page_ptr(kvm, gpa, &page, false);
	if (!ptr_page) {
		ec = -KVM_ENOENT;
		goto out;
	}

	ptr = ptr_page + (gpa & ~PAGE_MASK);
	ptr_size = size;

out:
	err = send(KVMI(kvm), ctx, ec, ptr, ptr_size);

	put_page_ptr(ptr_page, page, false);
	srcu_read_unlock(&kvm->srcu, srcu_idx);
	return err;
}

int kvmi_cmd_write_physical(struct kvm *kvm, u64 gpa, u64 size, const void *buf)
{
	int srcu_idx, ec = 0;
	struct page *page;
	void *ptr;

	srcu_idx = srcu_read_lock(&kvm->srcu);

	ptr = get_page_ptr(kvm, gpa, &page, true);
	if (!ptr) {
		ec = -KVM_ENOENT;
	} else {
		memcpy(ptr + (gpa & ~PAGE_MASK), buf, size);
		put_page_ptr(ptr, page, true);
	}

	srcu_read_unlock(&kvm->srcu, srcu_idx);
	return ec;
}

static struct kvmi_job *kvmi_pull_job(struct kvm_vcpu_introspection *vcpui)
{
	struct kvmi_job *job = NULL;

	spin_lock(&vcpui->job_lock);
	job = list_first_entry_or_null(&vcpui->job_list, typeof(*job), link);
	if (job)
		list_del(&job->link);
	spin_unlock(&vcpui->job_lock);

	return job;
}

void kvmi_run_jobs(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	struct kvmi_job *job;

	while ((job = kvmi_pull_job(vcpui))) {
		job->fct(vcpu, job->ctx);
		kvmi_free_job(job);
	}
}

static int kvmi_vcpu_kill(int sig, struct kvm_vcpu *vcpu)
{
	struct kernel_siginfo siginfo[1] = {};
	int err = -ESRCH;
	struct pid *pid;

	rcu_read_lock();
	pid = rcu_dereference(vcpu->pid);
	if (pid)
		err = kill_pid_info(sig, siginfo, pid);
	rcu_read_unlock();

	return err;
}

static void kvmi_vm_shutdown(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	int i;

	kvm_for_each_vcpu(i, vcpu, kvm)
		kvmi_vcpu_kill(SIGTERM, vcpu);
}

void kvmi_handle_common_event_actions(struct kvm *kvm,
				      u32 action, const char *str)
{
	switch (action) {
	case KVMI_EVENT_ACTION_CRASH:
		kvmi_vm_shutdown(kvm);
		break;

	default:
		kvmi_err(KVMI(kvm), "Unsupported action %d for event %s\n",
			 action, str);
	}
}

static void kvmi_vcpu_pause_event(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	u32 action;

	atomic_dec(&vcpui->pause_requests);

	trace_kvmi_event_pause_vcpu_send(vcpu->vcpu_id);

	action = kvmi_msg_send_vcpu_pause(vcpu);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		break;
	default:
		kvmi_handle_common_event_actions(vcpu->kvm, action, "PAUSE");
	}

	trace_kvmi_event_pause_vcpu_recv(vcpu->vcpu_id, action);
}

void kvmi_send_pending_event(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);

	if (vcpui->exception.send_event) {
		vcpui->exception.send_event = false;
		kvmi_arch_trap_event(vcpu);
	}
}

static int kvmi_wait_singlestep_insn(struct kvm_vcpu *vcpu)
{
	struct swait_queue_head *wq = kvm_arch_vcpu_wq(vcpu);
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	struct kvm_introspection *kvmi = KVMI(vcpu->kvm);
	int err = 0;

	while (atomic_read(&kvmi->singlestep.active) && !err) {
		kvmi_run_jobs(vcpu);

		err = swait_event_killable_exclusive(*wq,
			!atomic_read(&kvmi->singlestep.active) ||
			!list_empty(&vcpui->job_list));
	}

	return err;
}

void kvmi_handle_requests(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	struct kvm_introspection *kvmi;

	kvmi = kvmi_get(vcpu->kvm);
	if (!kvmi)
		goto out;

	kvmi_send_pending_event(vcpu);

	for (;;) {
		if (!vcpui->singlestep.owner)
			if (kvmi_wait_singlestep_insn(vcpu))
				break;

		kvmi_run_jobs(vcpu);

		if (atomic_read(&vcpui->pause_requests))
			kvmi_vcpu_pause_event(vcpu);
		else
			break;
	}

	kvmi_put(vcpu->kvm);

out:
	if (kvmi_arch_restore_interception(vcpu)) {
		mutex_lock(&vcpu->kvm->kvmi_lock);
		kvmi_arch_vcpu_free(vcpu);
		mutex_unlock(&vcpu->kvm->kvmi_lock);
	}
}

int kvmi_cmd_vcpu_pause(struct kvm_vcpu *vcpu, bool wait)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);

	if (atomic_read(&vcpui->pause_requests) > MAX_PAUSE_REQUESTS)
		return -KVM_EBUSY;

	atomic_inc(&vcpui->pause_requests);

	kvmi_make_request(vcpu, wait);

	return 0;
}

int kvmi_cmd_vcpu_set_registers(struct kvm_vcpu *vcpu,
				const struct kvm_regs *regs)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);

	if (!vcpui->waiting_for_reply)
		return -KVM_EOPNOTSUPP;

	memcpy(&vcpui->delayed_regs, regs, sizeof(vcpui->delayed_regs));
	vcpui->have_delayed_regs = true;

	return 0;
}

void kvmi_post_reply(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);

	if (vcpui->have_delayed_regs) {
		kvm_arch_vcpu_set_regs(vcpu, &vcpui->delayed_regs, false);
		vcpui->have_delayed_regs = false;
	}
}

bool kvmi_hypercall_event(struct kvm_vcpu *vcpu)
{
	struct kvm_introspection *kvmi;
	bool ret = false;

	if (!kvmi_arch_is_agent_hypercall(vcpu))
		return ret;

	kvmi = kvmi_get(vcpu->kvm);
	if (!kvmi)
		return ret;

	if (is_event_enabled(vcpu, KVMI_EVENT_HYPERCALL)) {
		kvmi_arch_hypercall_event(vcpu);
		ret = true;
	}

	kvmi_put(vcpu->kvm);

	return ret;
}

bool kvmi_breakpoint_event(struct kvm_vcpu *vcpu, u64 gva, u8 insn_len)
{
	struct kvm_introspection *kvmi;
	bool ret = false;

	kvmi = kvmi_get(vcpu->kvm);
	if (!kvmi)
		return true;

	if (is_event_enabled(vcpu, KVMI_EVENT_BREAKPOINT))
		kvmi_arch_breakpoint_event(vcpu, gva, insn_len);
	else
		ret = true;

	kvmi_put(vcpu->kvm);

	return ret;
}
EXPORT_SYMBOL(kvmi_breakpoint_event);

static void kvmi_inject_pending_exception(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);

	kvmi_arch_inject_pending_exception(vcpu);

	vcpui->exception.pending = false;

	kvm_make_request(KVM_REQ_INTROSPECTION, vcpu);
	vcpui->exception.send_event = true;
}

void kvmi_enter_guest(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_introspection *vcpui;
	struct kvm_introspection *kvmi;

	kvmi = kvmi_get(vcpu->kvm);
	if (kvmi) {
		vcpui = VCPUI(vcpu);

		if (vcpui->singlestep.loop)
			kvmi_arch_start_singlestep(vcpu);
		else if (vcpui->exception.pending)
			kvmi_inject_pending_exception(vcpu);

		kvmi_put(vcpu->kvm);
	}
}

static struct kvmi_mem_access *
__kvmi_get_saved_gfn_access(struct kvm_introspection *kvmi,
				const gfn_t gfn, u16 view)
{
	return radix_tree_lookup(&kvmi->access_tree[view], gfn);
}

static void kvmi_set_mem_access(struct kvm *kvm, gfn_t gfn, u8 access,
				u8 mask, u32 write_bitmap, u16 view)
{
	struct kvm_memory_slot *slot;
	int idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);

	slot = gfn_to_memslot(kvm, gfn);
	if (!slot)
		goto out;

	kvmi_arch_update_page_tracking(kvm, slot, gfn, access, mask, view);
	if (mask == rwx_access)
		kvmi_arch_set_subpage_access(kvm, slot, gfn, write_bitmap);

out:
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);
}

static int kvmi_set_gfn_access(struct kvm *kvm, gfn_t gfn, u8 access,
			       u32 write_bitmap, u16 view)
{
	u8 mask = rwx_access;

	kvmi_set_mem_access(kvm, gfn, access, mask, write_bitmap, view);

	return 0;
}

int kvmi_cmd_set_page_access(struct kvm_introspection *kvmi, u64 gpa, u8 access,
			     u16 view)
{
	u32 write_bitmap = default_write_bitmap;
	gfn_t gfn = gpa_to_gfn(gpa);
	u8 ignored_access;

	if (access & KVMI_PAGE_ACCESS_W)
		write_bitmap = ~default_write_bitmap;
	else
		kvmi_get_gfn_access(kvmi, gfn, &ignored_access, &write_bitmap,
				    view);

	return kvmi_set_gfn_access(kvmi->kvm, gfn, access, write_bitmap, view);
}

static int kvmi_get_gfn_access(struct kvm_introspection *kvmi, const gfn_t gfn,
			       u8 *access, u32 *write_bitmap, u16 view)
{
	struct kvm_memory_slot *slot = NULL;
	u8 allowed = rwx_access;
	u32 bitmap = default_write_bitmap;
	bool restricted;
	int idx;

	idx = srcu_read_lock(&kvmi->kvm->srcu);
	slot = gfn_to_memslot(kvmi->kvm, gfn);
	srcu_read_unlock(&kvmi->kvm->srcu, idx);

	if (slot)
		allowed = kvmi_get_gfn_access_from_slot(slot, gfn, view,
							&bitmap);

	restricted = (allowed & rwx_access) != rwx_access;

	if (!restricted)
		return -1;

	*access = allowed;
	*write_bitmap = bitmap;

	return 0;
}

static bool spp_access_allowed(gpa_t gpa, unsigned long bitmap)
{
	u32 off = (gpa & ~PAGE_MASK);
	u32 spp = off / 128;

	return test_bit(spp, &bitmap);
}

static bool kvmi_restricted_access(struct kvm_introspection *kvmi, gpa_t gpa,
				   u8 access, u16 view)
{
	u32 allowed_bitmap;
	u8 allowed_access;
	int err;

	err = kvmi_get_gfn_access(kvmi, gpa_to_gfn(gpa), &allowed_access,
				  &allowed_bitmap, view);

	if (err)
		return false;

	/*
	 * We want to be notified only for violations involving access
	 * bits that we've specifically cleared
	 */
	if ((~allowed_access) & access) {
		bool write_access = (access & KVMI_PAGE_ACCESS_W);

		if (write_access && spp_access_allowed(gpa, allowed_bitmap))
			return false;

		return true;
	}

	return false;
}

static bool is_pf_of_interest(struct kvm_vcpu *vcpu, gpa_t gpa, u8 access)
{
	struct kvm *kvm = vcpu->kvm;

	return kvmi_restricted_access(KVMI(kvm), gpa, access,
					kvm_get_ept_view(vcpu));
}

/*
 * The custom input is defined by a virtual address and size, and all reads
 * must be within this space. Reads that are completely outside should be
 * satisfyied using guest memory. Overlapping reads are erroneous.
 */
static int use_custom_input(struct kvm_vcpu *vcpu, gva_t gva, u8 *new,
			    int bytes)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	unsigned int offset;

	if (!vcpui->custom_ro_data.size || !bytes)
		return 0;

	if (bytes < 0 || bytes > vcpui->custom_ro_data.size) {
		kvmi_warn_once(KVMI(vcpu->kvm),
			       "%s: invalid range %d max %lu\n",
			       __func__, bytes, vcpui->custom_ro_data.size);
		return 0;
	}

	if (gva + bytes <= vcpui->custom_ro_data.addr ||
	    gva >= vcpui->custom_ro_data.addr + vcpui->custom_ro_data.size)
		return 0;

	if (gva < vcpui->custom_ro_data.addr &&
	    gva + bytes > vcpui->custom_ro_data.addr) {
		kvmi_warn_once(KVMI(vcpu->kvm),
			       "%s: read ranges overlap: 0x%lx:%d, 0x%llx:%lu\n",
			       __func__, gva, bytes, vcpui->custom_ro_data.addr,
			       vcpui->custom_ro_data.size);
		return 0;
	}

	if (gva + bytes > vcpui->custom_ro_data.addr
			+ vcpui->custom_ro_data.size) {
		kvmi_warn_once(KVMI(vcpu->kvm),
			       "%s: read ranges overlap: 0x%lx:%d, 0x%llx:%lu\n",
			       __func__, gva, bytes, vcpui->custom_ro_data.addr,
			       vcpui->custom_ro_data.size);
		return 0;
	}

	offset = gva - vcpui->custom_ro_data.addr;

	memcpy(new, vcpui->custom_ro_data.data + offset, bytes);

	return bytes;
}

static bool __kvmi_track_preread(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
				 u8 *new, int bytes, bool *data_ready)
{
	bool ret;

	if (!is_pf_of_interest(vcpu, gpa, KVMI_PAGE_ACCESS_R))
		return true;

	if (use_custom_input(vcpu, gva, new, bytes))
		goto out_custom;

	ret = kvmi_arch_pf_event(vcpu, gpa, gva, KVMI_PAGE_ACCESS_R);

	if (ret && use_custom_input(vcpu, gva, new, bytes))
		goto out_custom;

	return ret;

out_custom:
	if (*data_ready)
		kvmi_err(KVMI(vcpu->kvm),
			"Override custom data from another tracker\n");

	*data_ready = true;

	return true;
}

static bool kvmi_track_preread(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
			       u8 *new, int bytes, bool *data_ready,
			       struct kvm_page_track_notifier_node *node)
{
	struct kvm_introspection *kvmi;
	bool ret = true;

	kvmi = kvmi_get(vcpu->kvm);
	if (!kvmi)
		return true;

	if (is_event_enabled(vcpu, KVMI_EVENT_PF))
		ret = __kvmi_track_preread(vcpu, gpa, gva, new, bytes,
					   data_ready);

	kvmi_put(vcpu->kvm);

	return ret;
}

static bool __kvmi_track_prewrite(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva)
{
	if (!is_pf_of_interest(vcpu, gpa, KVMI_PAGE_ACCESS_W))
		return true;

	return kvmi_arch_pf_event(vcpu, gpa, gva, KVMI_PAGE_ACCESS_W);
}

static bool kvmi_track_prewrite(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
				const u8 *new, int bytes,
				struct kvm_page_track_notifier_node *node)
{
	struct kvm_introspection *kvmi;
	bool ret = true;

	kvmi = kvmi_get(vcpu->kvm);
	if (!kvmi)
		return true;

	if (is_event_enabled(vcpu, KVMI_EVENT_PF))
		ret = __kvmi_track_prewrite(vcpu, gpa, gva);

	kvmi_put(vcpu->kvm);

	return ret;
}

static bool __kvmi_track_preexec(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva)
{
	if (!is_pf_of_interest(vcpu, gpa, KVMI_PAGE_ACCESS_X))
		return true;

	return kvmi_arch_pf_event(vcpu, gpa, gva, KVMI_PAGE_ACCESS_X);
}

static bool kvmi_track_preexec(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
			       struct kvm_page_track_notifier_node *node)
{
	struct kvm_introspection *kvmi;
	bool ret = true;

	kvmi = kvmi_get(vcpu->kvm);
	if (!kvmi)
		return true;

	if (is_event_enabled(vcpu, KVMI_EVENT_PF))
		ret = __kvmi_track_preexec(vcpu, gpa, gva);

	kvmi_put(vcpu->kvm);

	return ret;
}

static void kvmi_track_restore_from_prev_slot(struct kvm *kvm,
		struct kvm_memory_slot *new_slot,
		gfn_t gfn,
		u16 view)
{
	struct kvm_memory_slot *old_slot = NULL;
	u32 write_bitmap;
	u8 old_access;

	old_slot = gfn_to_memslot(kvm, gfn);

	if (old_slot && old_slot->id != new_slot->id) {
		old_access = kvmi_get_gfn_access_from_slot(old_slot, gfn, view,
							   &write_bitmap);
		if (old_access != full_access) {
			kvmi_arch_update_page_tracking(kvm,
					new_slot,
					gfn,
					old_access,
					full_access,
					view);
			kvmi_arch_set_subpage_access(kvm, new_slot, gfn,
						     write_bitmap);
		}
	}
}

static void kvmi_track_create_slot(struct kvm *kvm,
				   struct kvm_memory_slot *slot,
				   unsigned long npages,
				   struct kvm_page_track_notifier_node *node)
{
	struct kvm_introspection *kvmi;
	gfn_t start = slot->base_gfn;
	const gfn_t end = start + npages;
	int idx;

	kvmi = kvmi_get(kvm);
	if (!kvmi)
		return;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	read_lock(&kvmi->access_tree_lock);

	while (start < end) {
		struct kvmi_mem_access *m;
		u16 view;

		for (view = 0; view < KVM_MAX_EPT_VIEWS; view++) {
			m = __kvmi_get_saved_gfn_access(kvmi, start, view);
			if (m) {
				kvmi_arch_update_page_tracking(kvm,
						slot,
						start,
						m->access,
						full_access,
						view);
				kvmi_arch_set_subpage_access(kvm, slot, start,
						     m->write_bitmap);
				radix_tree_delete(&kvmi->access_tree[view],
						m->gfn);
				kmem_cache_free(radix_cache, m);
			} else
				kvmi_track_restore_from_prev_slot(kvm, slot,
						start, view);
		}
		start++;
	}

	read_unlock(&kvmi->access_tree_lock);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	kvmi_put(kvm);
}

static const struct {
	unsigned int allow_bit;
	enum kvm_page_track_mode track_mode;
} track_modes[] = {
	{ KVMI_PAGE_ACCESS_R,   KVM_PAGE_TRACK_PREREAD },
	{ KVMI_PAGE_ACCESS_W,   KVM_PAGE_TRACK_PREWRITE },
	{ KVMI_PAGE_ACCESS_X,   KVM_PAGE_TRACK_PREEXEC },
	{ KVMI_PAGE_SVE,        KVM_PAGE_TRACK_SVE },
};

static u8 kvmi_get_gfn_access_from_slot(struct kvm_memory_slot *slot,
					gfn_t gfn, u16 view,
					u32 *write_bitmap)
{
	u64 offset = gfn - slot->base_gfn;
	u8 access = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(track_modes); i++) {
		unsigned int allow_bit = track_modes[i].allow_bit;
		enum kvm_page_track_mode mode = track_modes[i].track_mode;
		bool kvmi_tracked = test_bit(offset,
				slot->arch.kvmi_track[view][mode]);

		if (!kvmi_tracked)
			access |= allow_bit;
	}

	*write_bitmap = kvmi_arch_get_subpage_access(slot, gfn, access);

	return access;
}

static void kvmi_insert_mem_access(struct kvm *kvm, gfn_t gfn, u8 access,
				   u32 write_bitmap, u16 view)
{
	struct kvm_introspection *kvmi;
	struct kvmi_mem_access *m;

	kvmi = kvmi_get(kvm);
	if (!kvmi)
		return;

	m = kmem_cache_zalloc(radix_cache, GFP_KERNEL);

	if (!m) {
		WARN_ON(!m);
		return;
	}

	m->gfn = gfn;
	m->access = access;
	m->write_bitmap = write_bitmap;

	if (WARN_ON(radix_tree_preload(GFP_KERNEL)))
		return;

	write_lock(&kvmi->access_tree_lock);
	radix_tree_insert(&kvmi->access_tree[view], gfn, m);
	write_unlock(&kvmi->access_tree_lock);

	radix_tree_preload_end();

	kvmi_put(kvm);
}

static void kvmi_track_flush_slot(struct kvm *kvm, struct kvm_memory_slot *slot,
				  struct kvm_page_track_notifier_node *node)
{
	gfn_t start = slot->base_gfn;
	const gfn_t end = start + slot->npages;
	u32 write_bitmap;
	u8 access;

	while (start < end) {
		u16 view;

		for (view = 0; view < KVM_MAX_EPT_VIEWS; view++) {
			access = kvmi_get_gfn_access_from_slot(slot,
					start, view, &write_bitmap);
			if (access != full_access) {
				kvmi_insert_mem_access(kvm, start,
						write_bitmap,
						access, view);
				/* Remove all restrictions */
				kvmi_arch_update_page_tracking(kvm,
						slot,
						start,
						full_access,
						full_access,
						view);
				kvmi_arch_set_subpage_access(kvm, slot,
						start,
						~default_write_bitmap);
			}
		}
		start++;
	}
}

bool kvmi_vcpu_running_singlestep(struct kvm_vcpu *vcpu)
{
	struct kvm_introspection *kvmi;
	bool ret;

	kvmi = kvmi_get(vcpu->kvm);
	if (!kvmi)
		return false;

	ret = VCPUI(vcpu)->singlestep.loop || VCPUI(vcpu)->singlestep.owner;

	kvmi_put(vcpu->kvm);

	return ret;
}
EXPORT_SYMBOL(kvmi_vcpu_running_singlestep);

static u32 kvmi_send_singlestep(struct kvm_vcpu *vcpu, bool success)
{
	struct kvmi_event_singlestep e;
	int err, action;

	memset(&e, 0, sizeof(e));
	e.failed = success ? 0 : 1;

	err = kvmi_send_event(vcpu, KVMI_EVENT_SINGLESTEP, &e, sizeof(e),
			      NULL, 0, &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	return action;
}

static void kvmi_singlestep_event(struct kvm_vcpu *vcpu, bool success)
{
	u32 action;

	if (!is_event_enabled(vcpu, KVMI_EVENT_SINGLESTEP))
		return;

	trace_kvmi_event_singlestep_send(vcpu->vcpu_id);

	action = kvmi_send_singlestep(vcpu, success);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		break;
	default:
		kvmi_handle_common_event_actions(vcpu->kvm, action,
						"SINGLESTEP");
	}

	trace_kvmi_event_singlestep_recv(vcpu->vcpu_id, action);
}

static int restore_original_page_content(struct kvm_vcpu *vcpu, gva_t gva,
					 u8 *src, size_t bytes)
{
	u8 *ptr_page, *ptr;
	struct page *page;
	gpa_t gpa;

	gpa = kvm_mmu_gva_to_gpa_system(vcpu, gva, 0, NULL);
	if (gpa == UNMAPPED_GVA)
		return -KVM_EINVAL;

	ptr_page = get_page_ptr(vcpu->kvm, gpa, &page, true);
	if (!ptr_page)
		return -KVM_EINVAL;

	ptr = ptr_page + (gpa & ~PAGE_MASK);

	memcpy(ptr, src, bytes);

	put_page_ptr(ptr_page, page, true);

	return 0;
}

static void restore_original_content(struct kvm_vcpu *vcpu)
{
	struct kvm_introspection *kvmi = KVMI(vcpu->kvm);
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	size_t bytes = kvmi->singlestep.custom_ro_data.size;
	gva_t gva = vcpui->custom_ro_data.addr;
	u8 *backup;
	int srcu_idx;

	if (!bytes)
		return;

	backup = kvmi->singlestep.custom_ro_data.data;
	srcu_idx = srcu_read_lock(&vcpu->kvm->srcu);

	while (bytes) {
		size_t offset = gva & ~PAGE_MASK;
		size_t chunk = min(bytes, PAGE_SIZE - offset);

		if (restore_original_page_content(vcpu, gva, backup, chunk))
			goto out;

		bytes -= chunk;
		backup += chunk;
		gva += chunk;
	}

out:
	srcu_read_unlock(&vcpu->kvm->srcu, srcu_idx);
	kvmi->singlestep.custom_ro_data.size = 0;
}

void kvmi_stop_singlestep_insn(struct kvm_vcpu *vcpu)
{
	struct kvm_introspection *kvmi = KVMI(vcpu->kvm);
	struct kvm_vcpu_introspection *vcpui;
	struct kvm *kvm = vcpu->kvm;
	int l;

	vcpui = VCPUI(vcpu);

	for (l = kvmi->singlestep.level; l--;)
		kvmi_set_gfn_access(kvm,
				    kvmi->singlestep.backup[l].gfn,
				    kvmi->singlestep.backup[l].old_access,
				    kvmi->singlestep.backup[l].old_write_bitmap,
				    kvm_get_ept_view(vcpu));

	kvmi->singlestep.level = 0;

	restore_original_content(vcpu);

	atomic_set(&kvmi->singlestep.active, false);
	/*
	 * Make the singlestep.active update visible
	 * before resuming all the other vCPUs.
	 */
	smp_mb__after_atomic();
	kvm_make_all_cpus_request(kvm, 0);

	vcpui->singlestep.owner = false;

	trace_kvmi_stop_singlestep(vcpu->vcpu_id);

	kvmi_arch_stop_singlestep(vcpu);
}

/*
 * This function is called (a) if the introspection tool has set the vCPU
 * in single-step mode with KVMI_VCPU_CONTROL_SINGLESTEP (singlestep.loop)
 * or (b) if the vCPU is single-stepped transparently for the introspection
 * tool due to a unimplemented instruction (singlestep.owner).
 */
static void kvmi_handle_singlestep_exit(struct kvm_vcpu *vcpu, bool success)
{
	struct kvm_vcpu_introspection *vcpui;
	struct kvm_introspection *kvmi;
	struct kvm *kvm = vcpu->kvm;

	kvmi = kvmi_get(kvm);
	if (!kvmi)
		return;

	vcpui = VCPUI(vcpu);

	if (vcpui->singlestep.loop)
		kvmi_singlestep_event(vcpu, success);
	else if (vcpui->singlestep.owner)
		kvmi_stop_singlestep_insn(vcpu);

	kvmi_put(kvm);
}

void kvmi_singlestep_done(struct kvm_vcpu *vcpu)
{
	kvmi_handle_singlestep_exit(vcpu, true);
}
EXPORT_SYMBOL(kvmi_singlestep_done);

void kvmi_singlestep_failed(struct kvm_vcpu *vcpu)
{
	kvmi_handle_singlestep_exit(vcpu, false);
}
EXPORT_SYMBOL(kvmi_singlestep_failed);

static bool __kvmi_tracked_gfn(struct kvm_introspection *kvmi, gfn_t gfn,
			       u16 view)
{
	u32 ignored_write_bitmap;
	u8 ignored_access;
	int err;

	err = kvmi_get_gfn_access(kvmi, gfn, &ignored_access,
				  &ignored_write_bitmap, view);

	return !err;
}

bool kvmi_tracked_gfn(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	struct kvm_introspection *kvmi;
	bool ret;

	kvmi = kvmi_get(vcpu->kvm);
	if (!kvmi)
		return false;

	ret = __kvmi_tracked_gfn(kvmi, gfn, kvm_get_ept_view(vcpu));

	kvmi_put(vcpu->kvm);

	return ret;
}

void kvmi_init_emulate(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_introspection *vcpui;
	struct kvm_introspection *kvmi;

	kvmi = kvmi_get(vcpu->kvm);
	if (!kvmi)
		return;

	vcpui = VCPUI(vcpu);

	vcpui->rep_complete = false;
	vcpui->effective_rep_complete = false;

	vcpui->custom_ro_data.size = 0;
	vcpui->custom_ro_data.addr = 0;

	kvmi_put(vcpu->kvm);
}
EXPORT_SYMBOL(kvmi_init_emulate);

/*
 * If the user has requested that events triggered by repetitive
 * instructions be suppressed after the first cycle, then this
 * function will effectively activate it. This ensures that we don't
 * prematurely suppress potential events (second or later) triggered
 * by an instruction during a single pass.
 */
void kvmi_activate_rep_complete(struct kvm_vcpu *vcpu)
{
	struct kvm_introspection *kvmi;

	kvmi = kvmi_get(vcpu->kvm);
	if (!kvmi)
		return;

	VCPUI(vcpu)->effective_rep_complete = VCPUI(vcpu)->rep_complete;

	kvmi_put(vcpu->kvm);
}
EXPORT_SYMBOL(kvmi_activate_rep_complete);

static u8 kvmi_translate_pf_error_code(u64 error_code)
{
	u8 access = 0;

	if (error_code & PFERR_USER_MASK)
		access |= KVMI_PAGE_ACCESS_R;
	if (error_code & PFERR_WRITE_MASK)
		access |= KVMI_PAGE_ACCESS_W;
	if (error_code & PFERR_FETCH_MASK)
		access |= KVMI_PAGE_ACCESS_X;

	return access;
}

static bool kvmi_acquire_singlestep_insn(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	struct kvm_introspection *kvmi = KVMI(vcpu->kvm);

	if (vcpui->singlestep.owner)
		return true;

	if (atomic_cmpxchg(&kvmi->singlestep.active, false, true) != false)
		return false;

	kvm_make_all_cpus_request(vcpu->kvm,
				  KVM_REQ_INTROSPECTION | KVM_REQUEST_WAIT);

	vcpui->singlestep.owner = true;
	kvmi->singlestep.custom_ro_data.size = 0;

	return true;
}

static int write_custom_data_to_page(struct kvm_vcpu *vcpu, gva_t gva,
				     u8 *backup, size_t bytes)
{
	u8 *ptr_page, *ptr;
	struct page *page;
	gpa_t gpa;

	gpa = kvm_mmu_gva_to_gpa_system(vcpu, gva, 0, NULL);
	if (gpa == UNMAPPED_GVA)
		return -KVM_EINVAL;

	ptr_page = get_page_ptr(vcpu->kvm, gpa, &page, true);
	if (!ptr_page)
		return -KVM_EINVAL;

	ptr = ptr_page + (gpa & ~PAGE_MASK);

	memcpy(backup, ptr, bytes);
	use_custom_input(vcpu, gva, ptr, bytes);

	put_page_ptr(ptr_page, page, true);

	return 0;
}

static int write_custom_data(struct kvm_vcpu *vcpu)
{
	struct kvm_introspection *kvmi = KVMI(vcpu->kvm);
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	size_t bytes = vcpui->custom_ro_data.size;
	gva_t gva = vcpui->custom_ro_data.addr;
	u8 *backup;
	int srcu_idx;

	if (kvmi->singlestep.custom_ro_data.size)
		return 0;

	if (!bytes)
		return 0;

	backup = kvmi->singlestep.custom_ro_data.data;
	srcu_idx = srcu_read_lock(&vcpu->kvm->srcu);

	while (bytes) {
		size_t offset = gva & ~PAGE_MASK;
		size_t chunk = min(bytes, PAGE_SIZE - offset);

		if (write_custom_data_to_page(vcpu, gva, backup, chunk)) {
			srcu_read_unlock(&vcpu->kvm->srcu, srcu_idx);
			return -KVM_EINVAL;
		}

		bytes -= chunk;
		backup += chunk;
		gva += chunk;
		kvmi->singlestep.custom_ro_data.size += chunk;
	}

	srcu_read_unlock(&vcpu->kvm->srcu, srcu_idx);

	return 0;
}

static bool kvmi_run_singlestep_insn(struct kvm_vcpu *vcpu, gpa_t gpa,
				     u8 access)
{
	struct kvm_introspection *kvmi = KVMI(vcpu->kvm);
	u8 l = kvmi->singlestep.level;
	gfn_t gfn = gpa_to_gfn(gpa);
	u8 old_access, new_access;
	u32 old_write_bitmap, new_write_bitmap;
	u16 view;
	int err;

	trace_kvmi_run_singlestep(vcpu, gpa, access, l,
				  VCPUI(vcpu)->custom_ro_data.size);

	kvmi_arch_start_singlestep(vcpu);

	err = write_custom_data(vcpu);
	if (err) {
		kvmi_err(kvmi, "writing custom data failed, err %d\n", err);
		return false;
	}

	view = kvm_get_ept_view(vcpu);
	err = kvmi_get_gfn_access(kvmi, gfn, &old_access, &old_write_bitmap,
				  view);
	/* likely was removed from radix tree due to rwx */
	if (err) {
		kvmi_warn_once(kvmi,
				"%s: gfn 0x%llx not found in the radix tree\n",
				__func__, gfn);
		return true;
	}

	if (l == SINGLESTEP_MAX_DEPTH - 1) {
		kvmi_err(kvmi, "singlestep limit reached\n");
		return false;
	}

	kvmi->singlestep.backup[l].gfn = gfn;
	kvmi->singlestep.backup[l].old_access = old_access;
	kvmi->singlestep.backup[l].old_write_bitmap = old_write_bitmap;
	kvmi->singlestep.level++;

	new_access = kvmi_arch_relax_page_access(old_access, access);
	new_write_bitmap = (new_access & KVMI_PAGE_ACCESS_W)
				? ~default_write_bitmap
				: old_write_bitmap;

	kvmi_set_gfn_access(vcpu->kvm, gfn, new_access, new_write_bitmap,
			    view);

	return true;
}

static bool kvmi_start_singlestep_insn(struct kvm_vcpu *vcpu, gpa_t gpa,
					u8 access)
{
	bool ret = false;

	while (!kvmi_acquire_singlestep_insn(vcpu)) {
		int err = kvmi_wait_singlestep_insn(vcpu);

		if (err) {
			kvmi_err(KVMI(vcpu->kvm), "kvmi_wait_singlestep_insn() has failed\n");
			goto out;
		}
	}

	ret = kvmi_run_singlestep_insn(vcpu, gpa, access);
	if (!ret)
		kvmi_stop_singlestep_insn(vcpu);

out:
	return ret;
}

static bool __kvmi_singlestep_insn(struct kvm_vcpu *vcpu, gpa_t gpa,
				   int *emulation_type)
{
	struct kvm_introspection *kvmi = KVMI(vcpu->kvm);
	u8 allowed_access, pf_access;
	u32 ignored_write_bitmap;
	gfn_t gfn = gpa_to_gfn(gpa);
	int err;

	if (kvmi_arch_invalid_insn(vcpu, emulation_type))
		return false;

	err = kvmi_get_gfn_access(kvmi, gfn, &allowed_access,
				  &ignored_write_bitmap,
				  kvm_get_ept_view(vcpu));
	if (err)
		return false;

	pf_access = kvmi_translate_pf_error_code(vcpu->arch.error_code);

	return kvmi_start_singlestep_insn(vcpu, gpa, pf_access);
}

bool kvmi_singlestep_insn(struct kvm_vcpu *vcpu, gpa_t gpa, int *emulation_type)
{
	struct kvm_introspection *kvmi;
	bool ret = false;

	kvmi = kvmi_get(vcpu->kvm);
	if (!kvmi)
		return false;

	ret = __kvmi_singlestep_insn(vcpu, gpa, emulation_type);

	kvmi_put(vcpu->kvm);

	return ret;
}

int kvmi_cmd_set_page_sve(struct kvm *kvm, gpa_t gpa, u16 view, bool suppress)
{
	u8 mask = KVMI_PAGE_SVE;
	u8 access = suppress ? KVMI_PAGE_SVE : 0;

	kvmi_set_mem_access(kvm, gpa_to_gfn(gpa), access, mask,
			    default_write_bitmap, view);

	return 0;
}

int kvmi_cmd_alloc_token(struct kvm *kvm, struct kvmi_map_mem_token *token)
{
	return kvmi_mem_generate_token(kvm, token);
}

static void kvmi_create_vcpu_event(struct kvm_vcpu *vcpu)
{
	u32 action;

	trace_kvmi_event_create_vcpu_send(vcpu->vcpu_id);

	action = kvmi_msg_send_create_vcpu(vcpu);

	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		break;
	default:
		kvmi_handle_common_event_actions(vcpu->kvm, action, "CREATE");
	}

	trace_kvmi_event_create_vcpu_recv(vcpu->vcpu_id, action);
}

int kvmi_cmd_set_page_write_bitmap(struct kvm_introspection *kvmi, u64 gpa,
				   u32 write_bitmap)
{
	gfn_t gfn = gpa_to_gfn(gpa);
	bool write_allowed_for_all;
	u32 ignored_write_bitmap;
	u8 access = rwx_access;
	u16 view = 0;

	kvmi_get_gfn_access(kvmi, gfn, &access, &ignored_write_bitmap, view);

	write_allowed_for_all = (write_bitmap == (u32)((1ULL << 32) - 1));
	if (write_allowed_for_all)
		access |= KVMI_PAGE_ACCESS_W;
	else
		access &= ~KVMI_PAGE_ACCESS_W;

	return kvmi_set_gfn_access(kvmi->kvm, gfn, access, write_bitmap, view);
}
