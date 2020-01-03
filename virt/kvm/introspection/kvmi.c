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

#define MAX_PAUSE_REQUESTS 1001

static struct kmem_cache *msg_cache;
static struct kmem_cache *job_cache;

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
}

static int kvmi_cache_create(void)
{
	msg_cache = kmem_cache_create("kvmi_msg", KVMI_MSG_SIZE_ALLOC,
				      4096, SLAB_ACCOUNT, NULL);
	job_cache = kmem_cache_create("kvmi_job",
				      sizeof(struct kvmi_job),
				      0, SLAB_ACCOUNT, NULL);

	if (!msg_cache || !job_cache) {
		kvmi_cache_destroy();

		return -1;
	}

	return 0;
}

int kvmi_init(void)
{
	return kvmi_cache_create();
}

void kvmi_uninit(void)
{
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

	return true;
}

static int create_vcpui(struct kvm_vcpu *vcpu)
{
	if (!alloc_vcpui(vcpu))
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
}

static void free_kvmi(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	int i;

	kvm_for_each_vcpu(i, vcpu, kvm)
		free_vcpui(vcpu);

	kfree(kvm->kvmi);
	kvm->kvmi = NULL;
}

void kvmi_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	mutex_lock(&vcpu->kvm->kvmi_lock);
	free_vcpui(vcpu);
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

	return 0;
}

static void kvmi_job_release_vcpu(struct kvm_vcpu *vcpu, void *ctx)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);

	atomic_set(&vcpui->pause_requests, 0);
	vcpui->waiting_for_reply = false;
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

	while (kvmi_msg_process(kvmi))
		;

	/*
	 * Signal userspace (which might wait for POLLHUP only)
	 * and prevent the vCPUs from sending other events.
	 */
	kvmi_sock_shutdown(kvmi);

	kvmi_release_vcpus(kvmi->kvm);

	kvmi_put(kvmi->kvm);
	return 0;
}

int kvmi_hook(struct kvm *kvm, const struct kvm_introspection_hook *hook)
{
	struct kvm_introspection *kvmi;
	int err = 0;

	mutex_lock(&kvm->kvmi_lock);

	if (kvm->kvmi) {
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
	if (!kvmi)
		return -EFAULT;

	if (!kvmi_unhook_event(kvmi))
		err = -ENOENT;

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

	return 0;
}

static unsigned long gfn_to_hva_safe(struct kvm *kvm, gfn_t gfn)
{
	unsigned long hva;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&kvm->srcu);
	hva = gfn_to_hva(kvm, gfn);
	srcu_read_unlock(&kvm->srcu, srcu_idx);

	return hva;
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

	hva = gfn_to_hva_safe(kvm, gpa_to_gfn(gpa));

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

static int get_first_vcpu(struct kvm *kvm, struct kvm_vcpu **vcpu)
{
	struct kvm_vcpu *v;

	if (!atomic_read(&kvm->online_vcpus))
		return -KVM_EINVAL;

	v = kvm_get_vcpu(kvm, 0);
	if (!v)
		return -KVM_EINVAL;

	*vcpu = v;

	return 0;
}

int kvmi_cmd_read_physical(struct kvm *kvm, u64 gpa, u64 size,
			   int (*send)(struct kvm_introspection *,
					const struct kvmi_msg_hdr *,
					int err, const void *buf, size_t),
			   const struct kvmi_msg_hdr *ctx)
{
	void *ptr_page = NULL, *ptr = NULL;
	struct page *page = NULL;
	struct kvm_vcpu *vcpu;
	size_t ptr_size = 0;
	int err, ec;

	ec = get_first_vcpu(kvm, &vcpu);

	if (ec)
		goto out;

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
	return err;
}

int kvmi_cmd_write_physical(struct kvm *kvm, u64 gpa, u64 size, const void *buf)
{
	struct kvm_vcpu *vcpu;
	struct page *page;
	void *ptr;
	int err;

	err = get_first_vcpu(kvm, &vcpu);

	if (err)
		return err;

	ptr = get_page_ptr(kvm, gpa, &page, true);
	if (!ptr)
		return -KVM_ENOENT;

	memcpy(ptr + (gpa & ~PAGE_MASK), buf, size);

	put_page_ptr(ptr, page, true);

	return 0;
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

	action = kvmi_msg_send_vcpu_pause(vcpu);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		break;
	default:
		kvmi_handle_common_event_actions(vcpu->kvm, action, "PAUSE");
	}
}

void kvmi_handle_requests(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	struct kvm_introspection *kvmi;

	kvmi = kvmi_get(vcpu->kvm);
	if (!kvmi)
		return;

	for (;;) {
		kvmi_run_jobs(vcpu);

		if (atomic_read(&vcpui->pause_requests))
			kvmi_vcpu_pause_event(vcpu);
		else
			break;
	}

	kvmi_put(vcpu->kvm);
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
