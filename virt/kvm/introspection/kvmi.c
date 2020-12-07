// SPDX-License-Identifier: GPL-2.0
/*
 * KVM Introspection
 *
 * Copyright (C) 2017-2020 Bitdefender S.R.L.
 *
 */
#include <linux/mmu_context.h>
#include <linux/kthread.h>
#include <linux/highmem.h>
#include "kvmi_int.h"

#define KVMI_NUM_COMMANDS __cmp((int)KVMI_NEXT_VM_MESSAGE, \
				(int)KVMI_NEXT_VCPU_MESSAGE, >)
#define KVMI_NUM_EVENTS   __cmp((int)KVMI_NEXT_VM_EVENT, \
				(int)KVMI_NEXT_VCPU_EVENT, >)

#define KVMI_MSG_SIZE_ALLOC (sizeof(struct kvmi_msg_hdr) + KVMI_MAX_MSG_SIZE)

#define MAX_PAUSE_REQUESTS 1001

static DECLARE_BITMAP(Kvmi_always_allowed_commands, KVMI_NUM_COMMANDS);
static DECLARE_BITMAP(Kvmi_known_events, KVMI_NUM_EVENTS);
static DECLARE_BITMAP(Kvmi_known_vm_events, KVMI_NUM_EVENTS);
static DECLARE_BITMAP(Kvmi_known_vcpu_events, KVMI_NUM_EVENTS);

static struct kmem_cache *msg_cache;
static struct kmem_cache *job_cache;
static struct kmem_cache *radix_cache;

static const u8 full_access  =	KVMI_PAGE_ACCESS_R |
				KVMI_PAGE_ACCESS_W |
				KVMI_PAGE_ACCESS_X;

void *kvmi_msg_alloc(void)
{
	return kmem_cache_zalloc(msg_cache, GFP_KERNEL);
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

bool kvmi_is_command_allowed(struct kvm_introspection *kvmi, u16 id)
{
	return id < KVMI_NUM_COMMANDS && test_bit(id, kvmi->cmd_allow_mask);
}

bool kvmi_is_event_allowed(struct kvm_introspection *kvmi, u16 id)
{
	return id < KVMI_NUM_EVENTS && test_bit(id, kvmi->event_allow_mask);
}

bool kvmi_is_known_event(u16 id)
{
	return id < KVMI_NUM_EVENTS && test_bit(id, Kvmi_known_events);
}

bool kvmi_is_known_vm_event(u16 id)
{
	return id < KVMI_NUM_EVENTS && test_bit(id, Kvmi_known_vm_events);
}

bool kvmi_is_known_vcpu_event(u16 id)
{
	return id < KVMI_NUM_EVENTS && test_bit(id, Kvmi_known_vcpu_events);
}

static bool kvmi_is_vm_event_enabled(struct kvm_introspection *kvmi, u16 id)
{
	return id < KVMI_NUM_EVENTS && test_bit(id, kvmi->vm_event_enable_mask);
}

static void kvmi_init_always_allowed_commands(void)
{
	bitmap_zero(Kvmi_always_allowed_commands, KVMI_NUM_COMMANDS);
	set_bit(KVMI_GET_VERSION, Kvmi_always_allowed_commands);
	set_bit(KVMI_VM_CHECK_COMMAND, Kvmi_always_allowed_commands);
	set_bit(KVMI_VM_CHECK_EVENT, Kvmi_always_allowed_commands);
}

static void kvmi_init_known_events(void)
{
	bitmap_zero(Kvmi_known_vm_events, KVMI_NUM_EVENTS);
	set_bit(KVMI_VM_EVENT_UNHOOK, Kvmi_known_vm_events);

	bitmap_zero(Kvmi_known_vcpu_events, KVMI_NUM_EVENTS);
	kvmi_arch_init_vcpu_events_mask(Kvmi_known_vcpu_events);
	set_bit(KVMI_VCPU_EVENT_PAUSE, Kvmi_known_vcpu_events);

	bitmap_or(Kvmi_known_events, Kvmi_known_vm_events,
		  Kvmi_known_vcpu_events, KVMI_NUM_EVENTS);
}

int kvmi_init(void)
{
	kvmi_init_always_allowed_commands();
	kvmi_init_known_events();

	return kvmi_cache_create();
}

int kvmi_version(void)
{
	return KVMI_VERSION;
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

static bool kvmi_alloc_vcpui(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_introspection *vcpui;

	vcpui = kzalloc(sizeof(*vcpui), GFP_KERNEL);
	if (!vcpui)
		return false;

	vcpui->ev_enable_mask = bitmap_zalloc(KVMI_NUM_EVENTS, GFP_KERNEL);
	if (!vcpui->ev_enable_mask) {
		kfree(vcpu);
		return false;
	}

	INIT_LIST_HEAD(&vcpui->job_list);
	spin_lock_init(&vcpui->job_lock);

	vcpu->kvmi = vcpui;

	return kvmi_arch_vcpu_alloc_interception(vcpu);
}

static int kvmi_create_vcpui(struct kvm_vcpu *vcpu)
{
	if (!kvmi_alloc_vcpui(vcpu))
		return -ENOMEM;

	return 0;
}

static void kvmi_free_vcpu_jobs(struct kvm_vcpu_introspection *vcpui)
{
	struct kvmi_job *cur, *next;

	list_for_each_entry_safe(cur, next, &vcpui->job_list, link) {
		list_del(&cur->link);
		kvmi_free_job(cur);
	}
}

static void kvmi_free_vcpui(struct kvm_vcpu *vcpu, bool restore_interception)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);

	if (!vcpui)
		return;

	kvmi_free_vcpu_jobs(vcpui);

	bitmap_free(vcpui->ev_enable_mask);

	kfree(vcpui);
	vcpu->kvmi = NULL;

	kvmi_arch_request_interception_cleanup(vcpu, restore_interception);
	kvmi_make_request(vcpu, false);
}

static void kvmi_clear_mem_access(struct kvm *kvm)
{
	struct kvm_introspection *kvmi = KVMI(kvm);
	struct radix_tree_iter iter;
	void **slot;
	int idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);

	radix_tree_for_each_slot(slot, &kvmi->access_tree, &iter, 0) {
		struct kvmi_mem_access *m = *slot;

		m->access = full_access;
		kvmi_arch_update_page_tracking(kvm, NULL, m);

		radix_tree_iter_delete(&kvmi->access_tree, &iter, slot);
		kmem_cache_free(radix_cache, m);
	}

	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);
}

static void kvmi_free(struct kvm *kvm)
{
	bool restore_interception = KVMI(kvm)->restore_on_unhook;
	struct kvm_vcpu *vcpu;
	int i;

	kvmi_clear_mem_access(kvm);

	kvm_for_each_vcpu(i, vcpu, kvm)
		kvmi_free_vcpui(vcpu, restore_interception);

	bitmap_free(kvm->kvmi->cmd_allow_mask);
	bitmap_free(kvm->kvmi->event_allow_mask);
	bitmap_free(kvm->kvmi->vm_event_enable_mask);

	kfree(kvm->kvmi);
	kvm->kvmi = NULL;
}

void kvmi_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	bool restore_interception = false;

	mutex_lock(&vcpu->kvm->kvmi_lock);
	kvmi_free_vcpui(vcpu, restore_interception);
	kvmi_arch_vcpu_free_interception(vcpu);
	mutex_unlock(&vcpu->kvm->kvmi_lock);
}

static struct kvm_introspection *
kvmi_alloc(struct kvm *kvm, const struct kvm_introspection_hook *hook)
{
	struct kvm_introspection *kvmi;
	struct kvm_vcpu *vcpu;
	int i;

	kvmi = kzalloc(sizeof(*kvmi), GFP_KERNEL);
	if (!kvmi)
		return NULL;

	kvmi->cmd_allow_mask = bitmap_zalloc(KVMI_NUM_COMMANDS, GFP_KERNEL);
	kvmi->event_allow_mask = bitmap_zalloc(KVMI_NUM_EVENTS, GFP_KERNEL);
	kvmi->vm_event_enable_mask = bitmap_zalloc(KVMI_NUM_EVENTS, GFP_KERNEL);
	if (!kvmi->cmd_allow_mask || !kvmi->event_allow_mask ||
	    !kvmi->vm_event_enable_mask) {
		bitmap_free(kvmi->cmd_allow_mask);
		bitmap_free(kvmi->event_allow_mask);
		bitmap_free(kvmi->vm_event_enable_mask);
		kfree(kvmi);
		return NULL;
	}

	BUILD_BUG_ON(sizeof(hook->uuid) != sizeof(kvmi->uuid));
	memcpy(&kvmi->uuid, &hook->uuid, sizeof(kvmi->uuid));

	kvmi->restore_on_unhook = true;

	bitmap_copy(kvmi->cmd_allow_mask, Kvmi_always_allowed_commands,
		    KVMI_NUM_COMMANDS);

	atomic_set(&kvmi->ev_seq, 0);

	INIT_RADIX_TREE(&kvmi->access_tree,
			GFP_KERNEL & ~__GFP_DIRECT_RECLAIM);
	rwlock_init(&kvmi->access_tree_lock);

	kvm_for_each_vcpu(i, vcpu, kvm) {
		int err = kvmi_create_vcpui(vcpu);

		if (err) {
			kvmi_free(kvm);
			return NULL;
		}
	}

	kvmi->kvm = kvm;

	return kvmi;
}

static void kvmi_destroy(struct kvm_introspection *kvmi)
{
	struct kvm *kvm = kvmi->kvm;

	kvmi_free(kvm);
}

static void kvmi_stop_recv_thread(struct kvm_introspection *kvmi)
{
	kvmi_sock_shutdown(kvmi);
}

static void __kvmi_unhook(struct kvm *kvm)
{
	struct kvm_introspection *kvmi = KVMI(kvm);

	wait_for_completion_killable(&kvm->kvmi_complete);

	kvmi_arch_unhook(kvm);
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

	kvmi_arch_hook(kvm);

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

	while (kvmi_msg_process(kvmi))
		;

	/* Signal userspace and prevent the vCPUs from sending events. */
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

static int kvmi_hook(struct kvm *kvm,
		     const struct kvm_introspection_hook *hook)
{
	struct kvm_introspection *kvmi;
	int err = 0;

	mutex_lock(&kvm->kvmi_lock);

	if (!ready_to_hook(kvm)) {
		err = -EEXIST;
		goto out;
	}

	kvmi = kvmi_alloc(kvm, hook);
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

int kvmi_ioctl_hook(struct kvm *kvm,
		    const struct kvm_introspection_hook *hook)
{
	if (hook->padding)
		return -EINVAL;

	return kvmi_hook(kvm, hook);
}

void kvmi_create_vm(struct kvm *kvm)
{
	mutex_init(&kvm->kvmi_lock);
}

void kvmi_destroy_vm(struct kvm *kvm)
{
	kvmi_unhook(kvm);
}

static int
kvmi_ioctl_get_feature(const struct kvm_introspection_feature *feat,
		       bool *allow, s32 *id, unsigned int nbits)
{
	s32 all_bits = -1;

	if (feat->id < 0 && feat->id != all_bits)
		return -EINVAL;

	if (feat->id > 0 && feat->id >= nbits)
		return -EINVAL;

	if (feat->allow > 1)
		return -EINVAL;

	*allow = feat->allow == 1;
	*id = feat->id;

	return 0;
}

static void kvmi_control_allowed_events(struct kvm_introspection *kvmi,
					s32 id, bool allow)
{
	s32 all_events = -1;

	if (allow) {
		if (id == all_events)
			bitmap_fill(kvmi->event_allow_mask, KVMI_NUM_EVENTS);
		else
			set_bit(id, kvmi->event_allow_mask);
	} else {
		if (id == all_events)
			bitmap_zero(kvmi->event_allow_mask, KVMI_NUM_EVENTS);
		else
			clear_bit(id, kvmi->event_allow_mask);
	}
}

int kvmi_ioctl_event(struct kvm *kvm,
		     const struct kvm_introspection_feature *feat)
{
	struct kvm_introspection *kvmi;
	bool allow;
	int err;
	s32 id;

	err = kvmi_ioctl_get_feature(feat, &allow, &id, KVMI_NUM_EVENTS);
	if (err)
		return err;

	mutex_lock(&kvm->kvmi_lock);

	kvmi = KVMI(kvm);
	if (kvmi)
		kvmi_control_allowed_events(kvmi, id, allow);
	else
		err = -EFAULT;

	mutex_unlock(&kvm->kvmi_lock);
	return err;
}

static int kvmi_control_allowed_commands(struct kvm_introspection *kvmi,
					 s32 id, bool allow)
{
	s32 all_commands = -1;

	if (allow) {
		if (id == all_commands)
			bitmap_fill(kvmi->cmd_allow_mask, KVMI_NUM_COMMANDS);
		else
			set_bit(id, kvmi->cmd_allow_mask);
	} else {
		if (id == all_commands)
			bitmap_copy(kvmi->cmd_allow_mask,
				    Kvmi_always_allowed_commands,
				    KVMI_NUM_COMMANDS);
		else if (test_bit(id, Kvmi_always_allowed_commands))
			return -EPERM;
		else
			clear_bit(id, kvmi->cmd_allow_mask);
	}

	return 0;
}

int kvmi_ioctl_command(struct kvm *kvm,
		       const struct kvm_introspection_feature *feat)
{
	struct kvm_introspection *kvmi;
	bool allow;
	int err;
	s32 id;

	err = kvmi_ioctl_get_feature(feat, &allow, &id, KVMI_NUM_COMMANDS);
	if (err)
		return err;

	mutex_lock(&kvm->kvmi_lock);

	kvmi = KVMI(kvm);
	if (kvmi)
		err = kvmi_control_allowed_commands(kvmi, id, allow);
	else
		err = -EFAULT;

	mutex_unlock(&kvm->kvmi_lock);
	return err;
}

static bool kvmi_unhook_event(struct kvm_introspection *kvmi)
{
	int err;

	if (!kvmi_is_vm_event_enabled(kvmi, KVMI_VM_EVENT_UNHOOK))
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
			       u16 event_id, bool enable)
{
	if (enable)
		set_bit(event_id, kvmi->vm_event_enable_mask);
	else
		clear_bit(event_id, kvmi->vm_event_enable_mask);

	return 0;
}

int kvmi_cmd_vcpu_control_events(struct kvm_vcpu *vcpu,
				 u16 event_id, bool enable)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	int err;

	err = kvmi_arch_cmd_control_intercept(vcpu, event_id, enable);
	if (err)
		return err;

	if (enable)
		set_bit(event_id, vcpui->ev_enable_mask);
	else
		clear_bit(event_id, vcpui->ev_enable_mask);

	return 0;
}

void kvmi_cmd_vm_control_cleanup(struct kvm_introspection *kvmi, bool enable)
{
	kvmi->restore_on_unhook = enable;
}

static long
get_user_pages_remote_unlocked(struct mm_struct *mm, unsigned long start,
				unsigned long nr_pages, unsigned int gup_flags,
				struct page **pages)
{
	struct vm_area_struct **vmas = NULL;
	int locked = 1;
	long r;

	mmap_read_lock(mm);
	r = get_user_pages_remote(mm, start, nr_pages, gup_flags,
				  pages, vmas, &locked);
	if (locked)
		mmap_read_unlock(mm);

	return r;
}

static void *get_page_ptr(struct kvm *kvm, gpa_t gpa, struct page **page,
			  bool write, int *srcu_idx)
{
	unsigned int flags = write ? FOLL_WRITE : 0;
	unsigned long hva;

	*page = NULL;

	*srcu_idx = srcu_read_lock(&kvm->srcu);
	hva = gfn_to_hva(kvm, gpa_to_gfn(gpa));

	if (kvm_is_error_hva(hva))
		goto out_err;

	if (get_user_pages_remote_unlocked(kvm->mm, hva, 1, flags, page) != 1)
		goto out_err;

	return write ? kmap_atomic(*page) : kmap(*page);
out_err:
	srcu_read_unlock(&kvm->srcu, *srcu_idx);
	return NULL;
}

static void put_page_ptr(struct kvm *kvm, void *ptr, struct page *page,
			 bool write, int srcu_idx)
{
	if (write)
		kunmap_atomic(ptr);
	else
		kunmap(ptr);

	put_page(page);

	srcu_read_unlock(&kvm->srcu, srcu_idx);
}

int kvmi_cmd_read_physical(struct kvm *kvm, u64 gpa, size_t size,
			   int (*send)(struct kvm_introspection *,
					const struct kvmi_msg_hdr *,
					int err, const void *buf, size_t),
			   const struct kvmi_msg_hdr *ctx)
{
	struct page *page;
	void *ptr_page;
	int srcu_idx;
	int err;

	ptr_page = get_page_ptr(kvm, gpa, &page, false, &srcu_idx);
	if (!ptr_page) {
		err = send(KVMI(kvm), ctx, -KVM_ENOENT, NULL, 0);
	} else {
		err = send(KVMI(kvm), ctx, 0,
			   ptr_page + (gpa & ~PAGE_MASK), size);

		put_page_ptr(kvm, ptr_page, page, false, srcu_idx);
	}

	return err;
}

int kvmi_cmd_write_physical(struct kvm *kvm, u64 gpa, size_t size,
			    const void *buf)
{
	int ec = -KVM_ENOENT;
	struct page *page;
	int srcu_idx;
	void *ptr;

	ptr = get_page_ptr(kvm, gpa, &page, true, &srcu_idx);
	if (ptr) {
		memcpy(ptr + (gpa & ~PAGE_MASK), buf, size);
		put_page_ptr(kvm, ptr, page, true, srcu_idx);
		ec = 0;
	}

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

static void kvmi_handle_unsupported_event_action(struct kvm *kvm)
{
	kvmi_sock_shutdown(KVMI(kvm));
}

void kvmi_handle_common_event_actions(struct kvm_vcpu *vcpu, u32 action)
{
	struct kvm *kvm = vcpu->kvm;

	switch (action) {
	case KVMI_EVENT_ACTION_CRASH:
		vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
		break;

	default:
		kvmi_handle_unsupported_event_action(kvm);
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
		kvmi_handle_common_event_actions(vcpu, action);
	}
}

void kvmi_handle_requests(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	struct kvm_introspection *kvmi;

	kvmi = kvmi_get(vcpu->kvm);
	if (!kvmi)
		goto out;

	kvmi_arch_send_pending_event(vcpu);

	for (;;) {
		kvmi_run_jobs(vcpu);

		if (atomic_read(&vcpui->pause_requests))
			kvmi_vcpu_pause_event(vcpu);
		else
			break;
	}

	kvmi_put(vcpu->kvm);

out:
	if (kvmi_arch_clean_up_interception(vcpu)) {
		mutex_lock(&vcpu->kvm->kvmi_lock);
		kvmi_arch_vcpu_free_interception(vcpu);
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

static bool __kvmi_hypercall_event(struct kvm_vcpu *vcpu)
{
	u32 action;
	bool ret;

	action = kvmi_msg_send_vcpu_hypercall(vcpu);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		ret = true;
		break;
	default:
		kvmi_handle_common_event_actions(vcpu, action);
		ret = false;
	}

	return ret;
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

	if (is_vcpu_event_enabled(vcpu, KVMI_VCPU_EVENT_HYPERCALL))
		ret = __kvmi_hypercall_event(vcpu);

	kvmi_put(vcpu->kvm);

	return ret;
}

bool kvmi_breakpoint_event(struct kvm_vcpu *vcpu, u64 gva, u8 insn_len)
{
	struct kvm_introspection *kvmi;
	bool ret = true;

	kvmi = kvmi_get(vcpu->kvm);
	if (!kvmi)
		return ret;

	if (is_vcpu_event_enabled(vcpu, KVMI_VCPU_EVENT_BREAKPOINT)) {
		kvmi_arch_breakpoint_event(vcpu, gva, insn_len);
		ret = false;
	}

	kvmi_put(vcpu->kvm);

	return ret;
}
EXPORT_SYMBOL(kvmi_breakpoint_event);

static struct kvmi_mem_access *
__kvmi_get_gfn_access(struct kvm_introspection *kvmi, const gfn_t gfn)
{
	return radix_tree_lookup(&kvmi->access_tree, gfn);
}

static void kvmi_update_mem_access(struct kvm *kvm, struct kvmi_mem_access *m)
{
	struct kvm_introspection *kvmi = KVMI(kvm);

	kvmi_arch_update_page_tracking(kvm, NULL, m);

	if (m->access == full_access) {
		radix_tree_delete(&kvmi->access_tree, m->gfn);
		kmem_cache_free(radix_cache, m);
	}
}

static void kvmi_insert_mem_access(struct kvm *kvm, struct kvmi_mem_access *m)
{
	struct kvm_introspection *kvmi = KVMI(kvm);

	radix_tree_insert(&kvmi->access_tree, m->gfn, m);
	kvmi_arch_update_page_tracking(kvm, NULL, m);
}

static void kvmi_set_mem_access(struct kvm *kvm, struct kvmi_mem_access *m,
				bool *used)
{
	struct kvm_introspection *kvmi = KVMI(kvm);
	struct kvmi_mem_access *found;
	int idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	write_lock(&kvmi->access_tree_lock);

	found = __kvmi_get_gfn_access(kvmi, m->gfn);
	if (found) {
		found->access = m->access;
		kvmi_update_mem_access(kvm, found);
	} else if (m->access != full_access) {
		kvmi_insert_mem_access(kvm, m);
		*used = true;
	}

	write_unlock(&kvmi->access_tree_lock);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);
}

int kvmi_set_gfn_access(struct kvm *kvm, gfn_t gfn, u8 access)
{
	struct kvmi_mem_access *m;
	bool used = false;
	int err = 0;

	m = kmem_cache_zalloc(radix_cache, GFP_KERNEL);
	if (!m)
		return -KVM_ENOMEM;

	m->gfn = gfn;
	m->access = access;

	if (radix_tree_preload(GFP_KERNEL))
		err = -KVM_ENOMEM;
	else
		kvmi_set_mem_access(kvm, m, &used);

	radix_tree_preload_end();

	if (!used)
		kmem_cache_free(radix_cache, m);

	return err;
}

static int kvmi_get_gfn_access(struct kvm_introspection *kvmi, const gfn_t gfn,
			       u8 *access)
{
	struct kvmi_mem_access *m;

	read_lock(&kvmi->access_tree_lock);
	m = __kvmi_get_gfn_access(kvmi, gfn);
	if (m)
		*access = m->access;
	read_unlock(&kvmi->access_tree_lock);

	return m ? 0 : -1;
}

static bool kvmi_restricted_page_access(struct kvm_introspection *kvmi,
					gpa_t gpa, u8 access)
{
	u8 allowed_access;
	int err;

	err = kvmi_get_gfn_access(kvmi, gpa_to_gfn(gpa), &allowed_access);
	if (err)
		return false;

	/*
	 * We want to be notified only for violations involving access
	 * bits that we've specifically cleared
	 */
	if (access & (~allowed_access))
		return true;

	return false;
}

bool kvmi_pf_event(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva, u8 access)
{
	bool ret = false;
	u32 action;

	if (!kvmi_restricted_page_access(KVMI(vcpu->kvm), gpa, access))
		return true;

	action = kvmi_msg_send_vcpu_pf(vcpu, gpa, gva, access);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		ret = true;
		break;
	case KVMI_EVENT_ACTION_RETRY:
		break;
	default:
		kvmi_handle_common_event_actions(vcpu, action);
	}

	return ret;
}

void kvmi_add_memslot(struct kvm *kvm, struct kvm_memory_slot *slot,
		      unsigned long npages)
{
	struct kvm_introspection *kvmi = KVMI(kvm);
	gfn_t start = slot->base_gfn;
	gfn_t end = start + npages;
	int idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	read_lock(&kvmi->access_tree_lock);

	while (start < end) {
		struct kvmi_mem_access *m;

		m = __kvmi_get_gfn_access(kvmi, start);
		if (m)
			kvmi_arch_update_page_tracking(kvm, slot, m);
		start++;
	}

	read_unlock(&kvmi->access_tree_lock);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);
}

void kvmi_remove_memslot(struct kvm *kvm, struct kvm_memory_slot *slot)
{
	struct kvm_introspection *kvmi = KVMI(kvm);
	gfn_t start = slot->base_gfn;
	gfn_t end = start + slot->npages;
	int idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	write_lock(&kvmi->access_tree_lock);

	while (start < end) {
		struct kvmi_mem_access *m;

		m = __kvmi_get_gfn_access(kvmi, start);
		if (m) {
			u8 prev_access = m->access;

			m->access = full_access;
			kvmi_arch_update_page_tracking(kvm, slot, m);
			m->access = prev_access;
		}
		start++;
	}

	write_unlock(&kvmi->access_tree_lock);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);
}

bool kvmi_vcpu_running_singlestep(struct kvm_vcpu *vcpu)
{
	struct kvm_introspection *kvmi;
	bool ret;

	kvmi = kvmi_get(vcpu->kvm);
	if (!kvmi)
		return false;

	ret = VCPUI(vcpu)->singlestep.loop;

	kvmi_put(vcpu->kvm);

	return ret;
}
EXPORT_SYMBOL(kvmi_vcpu_running_singlestep);
