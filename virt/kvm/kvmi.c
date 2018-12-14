// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection
 *
 * Copyright (C) 2017-2018 Bitdefender S.R.L.
 *
 */
#include <linux/mmu_context.h>
#include <uapi/linux/kvmi.h>
#include <uapi/asm/kvmi.h>
#include "../../arch/x86/kvm/x86.h"
#include "../../arch/x86/kvm/mmu.h"
#include <asm/vmx.h>
#include "cpuid.h"
#include "kvmi_int.h"
#include <asm/kvm_page_track.h>
#include <linux/kthread.h>
#include <linux/bitmap.h>

/* TODO: split this into arch-independent and x86 */

#define CREATE_TRACE_POINTS
#include <trace/events/kvmi.h>

struct kvmi_mem_access {
	struct list_head link;
	gfn_t gfn;
	u8 access;
	bool active[KVM_PAGE_TRACK_MAX][KVM_MEM_SLOTS_NUM];
};

static bool kvmi_create_vcpu_event(struct kvm_vcpu *vcpu);
static void kvmi_abort_events(struct kvm *kvm);
static bool kvmi_page_fault_event(struct kvm_vcpu *vcpu, unsigned long gpa,
	unsigned long gva, u8 access);
static bool kvmi_track_preread(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
	u8 *new, int bytes, struct kvm_page_track_notifier_node *node,
	bool *data_ready);
static bool kvmi_track_prewrite(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
	const u8 *new, int bytes, struct kvm_page_track_notifier_node *node);
static bool kvmi_track_preexec(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
	struct kvm_page_track_notifier_node *node);
static void kvmi_track_create_slot(struct kvm *kvm,
	struct kvm_memory_slot *slot, unsigned long npages,
	struct kvm_page_track_notifier_node *node);
static void kvmi_track_flush_slot(struct kvm *kvm, struct kvm_memory_slot *slot,
	struct kvm_page_track_notifier_node *node);
static bool kvmi_start_ss(struct kvm_vcpu *vcpu, u64 gpa, u8 access);

static const u8 full_access  =	KVMI_PAGE_ACCESS_R |
				KVMI_PAGE_ACCESS_W |
				KVMI_PAGE_ACCESS_X;

static const struct {
	unsigned int allow_bit;
	enum kvm_page_track_mode track_mode;
} track_modes[] = {
	{ KVMI_PAGE_ACCESS_R, KVM_PAGE_TRACK_PREREAD },
	{ KVMI_PAGE_ACCESS_W, KVM_PAGE_TRACK_PREWRITE },
	{ KVMI_PAGE_ACCESS_X, KVM_PAGE_TRACK_PREEXEC },
};

static void kvmi_update_page_tracking(struct kvm *kvm,
				      struct kvm_memory_slot *slot,
				      struct kvmi_mem_access *m)
{
	int i;

	if (!slot) {
		slot = gfn_to_memslot(kvm, m->gfn);
		if (!slot)
			return;
	}

	trace_kvmi_set_gfn_access(m->gfn, m->access, slot->id);

	for (i = 0; i < ARRAY_SIZE(track_modes); i++) {
		unsigned int allow_bit = track_modes[i].allow_bit;
		enum kvm_page_track_mode mode = track_modes[i].track_mode;

		if (m->access & allow_bit) {
			if (m->active[mode][slot->id]) {
				kvm_slot_page_track_remove_page(kvm, slot,
					m->gfn, mode);
				m->active[mode][slot->id] = false;
			}
		} else if (!m->active[mode][slot->id]) {
			kvm_slot_page_track_add_page(kvm, slot, m->gfn, mode);
			m->active[mode][slot->id] = true;
		}
	}
}

static struct kvmi_mem_access *__kvmi_get_gfn_access(struct kvmi *ikvm,
						     const gfn_t gfn)
{
	return radix_tree_lookup(&ikvm->access_tree, gfn);
}

static struct kvmi_mem_access *kvmi_get_gfn_access(struct kvmi *ikvm,
						   const gfn_t gfn)
{
	struct kvmi_mem_access *m;

	read_lock(&ikvm->access_tree_lock);
	m = __kvmi_get_gfn_access(ikvm, gfn);
	read_unlock(&ikvm->access_tree_lock);

	return m;
}

static int kvmi_set_gfn_access(struct kvm *kvm, gfn_t gfn, u8 access)
{
	struct kvmi_mem_access *m;
	struct kvmi_mem_access *__m;
	struct kvmi *ikvm = IKVM(kvm);
	int idx;

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return -KVM_ENOMEM;

	INIT_LIST_HEAD(&m->link);
	m->gfn = gfn;
	m->access = access;

	if (radix_tree_preload(GFP_KERNEL)) {
		kfree(m);
		return -KVM_ENOMEM;
	}

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	write_lock(&ikvm->access_tree_lock);

	__m = __kvmi_get_gfn_access(ikvm, gfn);
	if (__m) {
		__m->access = access;
		kvmi_update_page_tracking(kvm, NULL, __m);
		if (access == full_access)
			radix_tree_delete(&ikvm->access_tree, gfn);
	} else {
		radix_tree_insert(&ikvm->access_tree, gfn, m);
		kvmi_update_page_tracking(kvm, NULL, m);
		m = NULL;
	}

	write_unlock(&ikvm->access_tree_lock);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	radix_tree_preload_end();

	kfree(m);

	return 0;
}

static bool kvmi_test_gfn_access(struct kvmi *ikvm, gfn_t gfn, u8 access)
{
	struct kvmi_mem_access *m;

	m = kvmi_get_gfn_access(ikvm, gfn);

	/*
	 * We want to be notified only for violations involving access
	 * bits that we've specifically cleared
	 */
	if (m && ((~m->access) & access))
		return true;

	return false;
}

bool kvmi_tracked_gfn(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	struct kvmi *ikvm;
	bool ret = false;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return false;

	ret = !!kvmi_get_gfn_access(IKVM(vcpu->kvm), gfn);

	kvmi_put(vcpu->kvm);

	return ret;
}

static void kvmi_free_mem_access(struct kvm *kvm)
{
	void **slot;
	struct radix_tree_iter iter;
	struct kvmi *ikvm = IKVM(kvm);
	int idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	write_lock(&ikvm->access_tree_lock);

	radix_tree_for_each_slot(slot, &ikvm->access_tree, &iter, 0) {
		struct kvmi_mem_access *m = *slot;

		m->access = full_access;
		kvmi_update_page_tracking(kvm, NULL, m);

		radix_tree_iter_delete(&ikvm->access_tree, &iter, slot);
		kfree(m);
	}

	write_unlock(&ikvm->access_tree_lock);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);
}

static unsigned long *msr_mask(struct kvm_vcpu *vcpu, unsigned int *msr)
{
	switch (*msr) {
	case 0 ... 0x1fff:
		return IVCPU(vcpu)->msr_mask.low;
	case 0xc0000000 ... 0xc0001fff:
		*msr &= 0x1fff;
		return IVCPU(vcpu)->msr_mask.high;
	}

	return NULL;
}

static bool test_msr_mask(struct kvm_vcpu *vcpu, unsigned int msr)
{
	unsigned long *mask = msr_mask(vcpu, &msr);

	if (!mask)
		return false;
	if (!test_bit(msr, mask))
		return false;

	return true;
}

static int msr_control(struct kvm_vcpu *vcpu, unsigned int msr, bool enable)
{
	unsigned long *mask = msr_mask(vcpu, &msr);

	if (!mask)
		return -KVM_EINVAL;
	if (enable)
		set_bit(msr, mask);
	else
		clear_bit(msr, mask);
	return 0;
}

static bool is_event_enabled(struct kvm_vcpu *vcpu, int event)
{
	return test_bit(event, IVCPU(vcpu)->ev_mask);
}

static int kvmi_control_events(struct kvm_vcpu *vcpu, unsigned long event_mask)
{
	int err = 0;
	struct kvm_guest_debug dbg = {};

	if (event_mask & KVMI_EVENT_BREAKPOINT_FLAG) {
		if (!is_event_enabled(vcpu, KVMI_EVENT_BREAKPOINT)) {
			dbg.control = KVM_GUESTDBG_ENABLE |
					KVM_GUESTDBG_USE_SW_BP;
			IVCPU(vcpu)->bp_intercepted = true;
			err = kvm_arch_vcpu_set_guest_debug(vcpu, &dbg);
		}
	} else {
		if (is_event_enabled(vcpu, KVMI_EVENT_BREAKPOINT)) {
			IVCPU(vcpu)->bp_intercepted = false;
			err = kvm_arch_vcpu_set_guest_debug(vcpu, &dbg);
		}
	}

	if (!err)
		bitmap_copy(IVCPU(vcpu)->ev_mask, &event_mask, KVMI_NUM_EVENTS);

	return err;
}

bool kvmi_bp_intercepted(struct kvm_vcpu *vcpu, u32 dbg)
{
	struct kvmi *ikvm;
	bool ret = false;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return false;

	if (IVCPU(vcpu)->bp_intercepted &&
		!(dbg & (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP))) {
		kvmi_warn_once(ikvm, "Trying to disable SW BP interception\n");
		ret = true;
	}

	kvmi_put(vcpu->kvm);

	return ret;
}
EXPORT_SYMBOL(kvmi_bp_intercepted);

unsigned int kvmi_vcpu_mode(const struct kvm_vcpu *vcpu,
	const struct kvm_sregs *sregs)
{
	unsigned int mode = 0;

	if (is_long_mode((struct kvm_vcpu *) vcpu)) {
		if (sregs->cs.l)
			mode = 8;
		else if (!sregs->cs.db)
			mode = 2;
		else
			mode = 4;
	} else if (sregs->cr0 & X86_CR0_PE) {
		if (!sregs->cs.db)
			mode = 2;
		else
			mode = 4;
	} else if (!sregs->cs.db) {
		mode = 2;
	} else {
		mode = 4;
	}

	return mode;
}

int kvmi_init(void)
{
	return kvmi_mem_init();
}

void kvmi_uninit(void)
{
	kvmi_mem_exit();
}

static bool alloc_kvmi(struct kvm *kvm, const struct kvm_introspection *qemu)
{
	struct kvmi *ikvm;

	ikvm = kzalloc(sizeof(*ikvm), GFP_KERNEL);
	if (!ikvm)
		return false;

	/* see comments of radix_tree_preload() - no direct reclaim */
	INIT_RADIX_TREE(&ikvm->access_tree, GFP_KERNEL & ~__GFP_DIRECT_RECLAIM);
	rwlock_init(&ikvm->access_tree_lock);

	atomic_set(&ikvm->proto.ev_seq, 0);
	INIT_LIST_HEAD(&ikvm->proto.rpl_waiters);
	spin_lock_init(&ikvm->proto.rpl_lock);

	/* TODO: qemu->commands qemu->events */
	ikvm->cmd_allow_mask = (-1 & KVMI_KNOWN_COMMANDS)
				| KVMI_GET_VERSION_FLAG;
	ikvm->event_allow_mask = -1 & KVMI_KNOWN_EVENTS;
	memcpy(&ikvm->uuid, &qemu->uuid, sizeof(ikvm->uuid));

	ikvm->kptn_node.track_preread = kvmi_track_preread;
	ikvm->kptn_node.track_prewrite = kvmi_track_prewrite;
	ikvm->kptn_node.track_preexec = kvmi_track_preexec;
	ikvm->kptn_node.track_create_slot = kvmi_track_create_slot;
	ikvm->kptn_node.track_flush_slot = kvmi_track_flush_slot;

	ikvm->kvm = kvm;
	kvm->kvmi = ikvm;

	return true;
}

int kvmi_add_job(struct kvm_vcpu *vcpu,
		 void (*fct)(struct kvm_vcpu *vcpu, void *ctx),
		 void *ctx)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvmi_job *job;

	job = kmalloc(sizeof(*job), GFP_KERNEL);
	if (unlikely(!job))
		return -ENOMEM;

	INIT_LIST_HEAD(&job->link);
	job->fct = fct;
	job->ctx = ctx;

	spin_lock(&ivcpu->job_lock);
	list_add_tail(&job->link, &ivcpu->job_list);
	spin_unlock(&ivcpu->job_lock);

	kvm_make_request(KVM_REQ_INTROSPECTION, vcpu);
	kvm_vcpu_kick(vcpu);

	return 0;
}

static struct kvmi_job *kvmi_pull_job(struct kvmi_vcpu *ivcpu)
{
	struct kvmi_job *job = NULL;

	spin_lock(&ivcpu->job_lock);
	job = list_first_entry_or_null(&ivcpu->job_list, typeof(*job), link);
	if (job)
		list_del(&job->link);
	spin_unlock(&ivcpu->job_lock);

	return job;
}

static void kvmi_job_create_vcpu(struct kvm_vcpu *vcpu, void *ctx)
{
	kvmi_create_vcpu_event(vcpu);
}

static bool alloc_ivcpu(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu;

	ivcpu = kzalloc(sizeof(*ivcpu), GFP_KERNEL);
	if (!ivcpu)
		return false;

	INIT_LIST_HEAD(&ivcpu->job_list);
	spin_lock_init(&ivcpu->job_lock);

	vcpu->kvmi = ivcpu;

	return true;
}

struct kvmi * __must_check kvmi_get(struct kvm *kvm)
{
	if (refcount_inc_not_zero(&kvm->kvmi_ref))
		return kvm->kvmi;

	return NULL;
}

/* This function may be called from atomic context and MUST not sleep !! */
void kvmi_put(struct kvm *kvm)
{
	int i;
	struct kvm_vcpu *vcpu;
	struct kvmi *ikvm = IKVM(kvm);

	/* end of introspection session here, start uninitialization */
	if (refcount_dec_and_test(&kvm->kvmi_ref)) {
		kvmi_sock_put(ikvm);
		kvmi_mem_link_down(kvm);

		kfree(kvm->kvmi);
		kvm->kvmi = NULL;

		kvm_for_each_vcpu(i, vcpu, kvm) {
			kfree(vcpu->kvmi);
			vcpu->kvmi = NULL;
		}

		complete(&kvm->kvmi_completed);
	}
}

/*
 * VCPU hotplug - this function will likely be called before VCPU will start
 * executing code
 */
int kvmi_vcpu_init(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm;
	int ret = 0;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return 0;

	if (!alloc_ivcpu(vcpu)) {
		kvmi_err(ikvm, "Unable to alloc ivcpu for vcpu %u\n",
			 vcpu->vcpu_id);
		ret = -ENOMEM;
		goto out;
	}

	if (kvmi_add_job(vcpu, kvmi_job_create_vcpu, NULL))
		ret = -ENOMEM;

out:
	kvmi_put(vcpu->kvm);

	return ret;
}

/*
 * VCPU hotplug - this function will likely be called after VCPU will stop
 * executing code
 */
void kvmi_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	/*
	 * Under certain circumstances (errors in creating the VCPU, hotplug?)
	 * this function may be reached with the KVMI member still allocated.
	 * This VCPU won't be reachable by the introspection engine, so no
	 * protection is necessary when de-allocating.
	 */
	kfree(vcpu->kvmi);
	vcpu->kvmi = NULL;
}

static bool is_tracked_gpa(struct kvm_vcpu *vcpu, gpa_t gpa, u8 access)
{
	struct kvm *kvm = vcpu->kvm;

	if (kvm_mmu_nested_pagefault(vcpu))
		return false;

	/* Have we shown interest in this page? */
	if (!kvmi_test_gfn_access(IKVM(kvm), gpa_to_gfn(gpa), access))
		return false;

	return true;
}

static bool use_custom_input(struct kvm_vcpu *vcpu, u8 *new, int bytes,
				bool *data_ready)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvmi *ikvm = IKVM(vcpu->kvm);
	int s;

	if (ivcpu->ctx_pos == ivcpu->ctx_size)
		return false;

	s = min_t(int, bytes, ivcpu->ctx_size - ivcpu->ctx_pos);

	memcpy(new, ivcpu->ctx_data + ivcpu->ctx_pos, s);
	ivcpu->ctx_pos += s;

	if (*data_ready)
		kvmi_err(ikvm, "Override custom data from another tracker\n");

	*data_ready = true;
	return true;
}

static bool __kvmi_track_preread(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
	u8 *new, int bytes, struct kvm_page_track_notifier_node *node,
	bool *data_ready)
{
	bool ret;

	if (!is_tracked_gpa(vcpu, gpa, KVMI_PAGE_ACCESS_R))
		return true;

	if (use_custom_input(vcpu, new, bytes, data_ready))
		return true;

	ret = kvmi_page_fault_event(vcpu, gpa, gva, KVMI_PAGE_ACCESS_R);

	if (ret)
		use_custom_input(vcpu, new, bytes, data_ready);

	return ret;
}

static bool kvmi_track_preread(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
	u8 *new, int bytes, struct kvm_page_track_notifier_node *node,
	bool *data_ready)
{
	struct kvmi *ikvm;
	bool ret = true;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return true;

	if (is_event_enabled(vcpu, KVMI_EVENT_PF))
		ret = __kvmi_track_preread(vcpu, gpa, gva, new, bytes, node,
					   data_ready);

	kvmi_put(vcpu->kvm);

	return ret;
}

static bool __kvmi_track_prewrite(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
	const u8 *new, int bytes,
	struct kvm_page_track_notifier_node *node)
{
	if (!is_tracked_gpa(vcpu, gpa, KVMI_PAGE_ACCESS_W))
		return true;

	return kvmi_page_fault_event(vcpu, gpa, gva, KVMI_PAGE_ACCESS_W);
}

static bool kvmi_track_prewrite(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
	const u8 *new, int bytes,
	struct kvm_page_track_notifier_node *node)
{
	struct kvmi *ikvm;
	bool ret = true;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return true;

	if (is_event_enabled(vcpu, KVMI_EVENT_PF))
		ret = __kvmi_track_prewrite(vcpu, gpa, gva, new, bytes, node);

	kvmi_put(vcpu->kvm);

	return ret;
}

static bool __kvmi_track_preexec(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
	struct kvm_page_track_notifier_node *node)
{
	if (!is_tracked_gpa(vcpu, gpa, KVMI_PAGE_ACCESS_X))
		return true;

	return kvmi_page_fault_event(vcpu, gpa, gva, KVMI_PAGE_ACCESS_X);
}

static bool kvmi_track_preexec(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
	struct kvm_page_track_notifier_node *node)
{
	struct kvmi *ikvm;
	bool ret = true;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return true;

	if (is_event_enabled(vcpu, KVMI_EVENT_PF))
		ret = __kvmi_track_preexec(vcpu, gpa, gva, node);

	kvmi_put(vcpu->kvm);

	return ret;
}

static void kvmi_track_create_slot(struct kvm *kvm,
	struct kvm_memory_slot *slot,
	unsigned long npages,
	struct kvm_page_track_notifier_node *node)
{
	struct kvmi *ikvm;
	gfn_t start = slot->base_gfn;
	const gfn_t end = start + npages;
	int idx;

	ikvm = kvmi_get(kvm);
	if (!ikvm)
		return;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	read_lock(&ikvm->access_tree_lock);

	while (start < end) {
		struct kvmi_mem_access *m;

		m = __kvmi_get_gfn_access(ikvm, start);
		if (m)
			kvmi_update_page_tracking(kvm, slot, m);
		start++;
	}

	read_unlock(&ikvm->access_tree_lock);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	kvmi_put(kvm);
}

static void kvmi_track_flush_slot(struct kvm *kvm, struct kvm_memory_slot *slot,
	struct kvm_page_track_notifier_node *node)
{
	struct kvmi *ikvm;
	gfn_t start = slot->base_gfn;
	const gfn_t end = start + slot->npages;
	int idx;

	ikvm = kvmi_get(kvm);
	if (!ikvm)
		return;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	write_lock(&ikvm->access_tree_lock);

	while (start < end) {
		struct kvmi_mem_access *m;

		m = __kvmi_get_gfn_access(ikvm, start);
		if (m) {
			u8 prev_access = m->access;

			m->access = full_access;
			kvmi_update_page_tracking(kvm, slot, m);
			m->access = prev_access;
		}

		start++;
	}

	write_unlock(&ikvm->access_tree_lock);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	kvmi_put(kvm);
}

static void kvmi_end_introspection(struct kvmi *ikvm)
{
	struct kvm *kvm = ikvm->kvm;

	/* Signal QEMU which is waiting for POLLHUP. */
	kvmi_sock_shutdown(ikvm);

	/*
	 * Trigger all the VCPUs out of waiting for replies. Although the
	 * introspection is still enabled, sending additional events will
	 * fail because the socket is shut down. Waiting will not be possible.
	 */
	kvmi_abort_events(kvm);

	/*
	 * This may sleep on synchronize_srcu() so it's not allowed to be
	 * called under kvmi_put().
	 * Also synchronize_srcu() may deadlock on (page tracking) read-side
	 * regions that are waiting for reply to events, so must be called
	 * after kvmi_abort_events().
	 */
	kvm_page_track_unregister_notifier(kvm, &ikvm->kptn_node);

	/*
	 * This function uses kvm->mmu_lock so it's not allowed to be
	 * called under kvmi_put(). It can reach a deadlock if called
	 * from kvm_mmu_load -> kvmi_tracked_gfn -> kvmi_put.
	 */
	kvmi_free_mem_access(kvm);

	/*
	 * At this moment the socket is shut down, no more commands will come
	 * from the introspector, and the only way into the introspection is
	 * thru the event handlers. Make sure the introspection ends.
	 */
	kvmi_put(kvm);
}

static int kvmi_recv(void *arg)
{
	struct kvmi *ikvm = arg;

	kvmi_info(ikvm, "Hooking VM\n");

	while (kvmi_msg_process(ikvm))
		;

	kvmi_info(ikvm, "Unhooking VM\n");

	kvmi_end_introspection(ikvm);

	return 0;
}

int kvmi_hook(struct kvm *kvm, const struct kvm_introspection *qemu)
{
	struct kvm_vcpu *vcpu;
	struct kvmi *ikvm;
	int i, err = 0;

	/* wait for the previous introspection to finish */
	err = wait_for_completion_killable(&kvm->kvmi_completed);
	if (err)
		return err;

	/* ensure no VCPU hotplug happens until we set the reference */
	mutex_lock(&kvm->lock);

	if (!alloc_kvmi(kvm, qemu)) {
		mutex_unlock(&kvm->lock);
		return -ENOMEM;
	}
	ikvm = IKVM(kvm);

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (!alloc_ivcpu(vcpu)) {
			err = -ENOMEM;
			goto err_alloc;
		}
		if (kvmi_add_job(vcpu, kvmi_job_create_vcpu, NULL)) {
			err = -ENOMEM;
			goto err_alloc;
		}
	}

	/* interact with other kernel components after structure allocation */
	if (!kvmi_sock_get(ikvm, qemu->fd)) {
		err = -EINVAL;
		goto err_alloc;
	}

	kvm_page_track_register_notifier(kvm, &ikvm->kptn_node);

	/*
	 * Make sure all the KVM/KVMI structures are linked and no pointer
	 * is read as NULL after the reference count has been set.
	 */
	smp_mb__before_atomic();
	refcount_set(&kvm->kvmi_ref, 1);

	mutex_unlock(&kvm->lock);

	ikvm->recv = kthread_run(kvmi_recv, ikvm, "kvmi-recv");
	if (IS_ERR(ikvm->recv)) {
		kvmi_err(ikvm, "Unable to create receiver thread!\n");
		err = PTR_ERR(ikvm->recv);
		goto err_recv;
	}

	return 0;

err_recv:
	/*
	 * introspection has oficially started since reference count has been
	 * set (and some event handlers may have already acquired it), but
	 * without the receiver thread; we must emulate its shutdown behavior
	 */
	kvmi_end_introspection(ikvm);

	return err;

err_alloc:
	kvm_for_each_vcpu(i, vcpu, kvm) {
		kfree(vcpu->kvmi);
		vcpu->kvmi = NULL;
	}

	kfree(kvm->kvmi);
	kvm->kvmi = NULL;

	mutex_unlock(&kvm->lock);

	return err;
}

void kvmi_create_vm(struct kvm *kvm)
{
	init_completion(&kvm->kvmi_completed);
	complete(&kvm->kvmi_completed);
}

void kvmi_destroy_vm(struct kvm *kvm)
{
	struct kvmi *ikvm;

	ikvm = kvmi_get(kvm);
	if (!ikvm)
		return;

	/* trigger socket shutdown - kvmi_recv() will start shutdown process */
	kvmi_sock_shutdown(ikvm);

	kvmi_put(kvm);

	/* wait for introspection resources to be released */
	wait_for_completion_killable(&kvm->kvmi_completed);
}

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

static bool kvmi_emul_unimplemented(struct kvm_vcpu *vcpu, u64 gpa)
{
	u8 access = kvmi_translate_pf_error_code(vcpu->arch.error_code);

	if (kvmi_start_ss(vcpu, gpa, access))
		return false;

	return true;
}

static bool __kvmi_track_emul_unimplemented(struct kvm_vcpu *vcpu, gpa_t gpa)
{
	struct kvm *kvm = vcpu->kvm;

	if (!kvmi_get_gfn_access(IKVM(kvm), gpa_to_gfn(gpa)))
		return true;

	return kvmi_emul_unimplemented(vcpu, gpa);
}

bool kvmi_track_emul_unimplemented(struct kvm_vcpu *vcpu, gpa_t gpa)
{
	struct kvmi *ikvm;
	bool ret = true;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return true;

	ret = __kvmi_track_emul_unimplemented(vcpu, gpa);

	kvmi_put(vcpu->kvm);

	return ret;
}

void kvmi_get_msrs(struct kvm_vcpu *vcpu, struct kvmi_event *event)
{
	struct msr_data msr;

	msr.host_initiated = true;

	msr.index = MSR_IA32_SYSENTER_CS;
	kvm_get_msr(vcpu, &msr);
	event->msrs.sysenter_cs = msr.data;

	msr.index = MSR_IA32_SYSENTER_ESP;
	kvm_get_msr(vcpu, &msr);
	event->msrs.sysenter_esp = msr.data;

	msr.index = MSR_IA32_SYSENTER_EIP;
	kvm_get_msr(vcpu, &msr);
	event->msrs.sysenter_eip = msr.data;

	msr.index = MSR_EFER;
	kvm_get_msr(vcpu, &msr);
	event->msrs.efer = msr.data;

	msr.index = MSR_STAR;
	kvm_get_msr(vcpu, &msr);
	event->msrs.star = msr.data;

	msr.index = MSR_LSTAR;
	kvm_get_msr(vcpu, &msr);
	event->msrs.lstar = msr.data;

	msr.index = MSR_CSTAR;
	kvm_get_msr(vcpu, &msr);
	event->msrs.cstar = msr.data;

	msr.index = MSR_IA32_CR_PAT;
	kvm_get_msr(vcpu, &msr);
	event->msrs.pat = msr.data;

	msr.index = MSR_KERNEL_GS_BASE;
	kvm_get_msr(vcpu, &msr);
	event->msrs.shadow_gs = msr.data;
}

static int kvmi_vcpu_kill(int sig, struct kvm_vcpu *vcpu)
{
	int err = -ESRCH;
	struct pid *pid;
	struct kernel_siginfo siginfo[1] = {};

	rcu_read_lock();
	pid = rcu_dereference(vcpu->pid);
	if (pid)
		err = kill_pid_info(sig, siginfo, pid);
	rcu_read_unlock();

	return err;
}

static void kvmi_vm_shutdown(struct kvm *kvm)
{
	int i;
	struct kvm_vcpu *vcpu;

	kvm_for_each_vcpu(i, vcpu, kvm)
		kvmi_vcpu_kill(SIGTERM, vcpu);
}

static void handle_common_event_actions(struct kvm_vcpu *vcpu, u32 action)
{
	struct kvm *kvm = vcpu->kvm;

	switch (action) {
	case KVMI_EVENT_ACTION_CRASH:
		kvmi_vm_shutdown(kvm);
		break;

	default:
		kvmi_err(IKVM(kvm), "Unsupported event action: %d\n", action);
	}
}

static bool __kvmi_cr_event(struct kvm_vcpu *vcpu, unsigned int cr,
	unsigned long old_value, unsigned long *new_value)
{
	u64 ret_value;
	u32 action;
	bool ret = false;

	if (old_value == *new_value)
		return true;
	if (!test_bit(cr, IVCPU(vcpu)->cr_mask))
		return true;

	trace_kvmi_event_cr_send(vcpu->vcpu_id, cr, old_value, *new_value);

	action = kvmi_msg_send_cr(vcpu, cr, old_value, *new_value, &ret_value);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		*new_value = ret_value;
		ret = true;
		break;
	default:
		handle_common_event_actions(vcpu, action);
	}

	trace_kvmi_event_cr_recv(vcpu->vcpu_id, action, ret_value);

	return ret;
}

bool kvmi_cr_event(struct kvm_vcpu *vcpu, unsigned int cr,
	unsigned long old_value, unsigned long *new_value)
{
	struct kvmi *ikvm;
	bool ret = true;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return true;

	if (is_event_enabled(vcpu, KVMI_EVENT_CR))
		ret = __kvmi_cr_event(vcpu, cr, old_value, new_value);

	kvmi_put(vcpu->kvm);

	return ret;
}

static bool __kvmi_msr_event(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	u64 ret_value;
	u32 action;
	bool ret = false;
	struct msr_data old_msr = {
		.host_initiated = true,
		.index = msr->index,
	};

	if (msr->host_initiated)
		return true;
	if (!test_msr_mask(vcpu, msr->index))
		return true;
	if (kvm_get_msr(vcpu, &old_msr))
		return true;
	if (old_msr.data == msr->data)
		return true;

	trace_kvmi_event_msr_send(vcpu->vcpu_id, msr->index, old_msr.data,
		msr->data);

	action = kvmi_msg_send_msr(vcpu, msr->index, old_msr.data, msr->data,
		&ret_value);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		msr->data = ret_value;
		ret = true;
		break;
	default:
		handle_common_event_actions(vcpu, action);
	}

	trace_kvmi_event_msr_recv(vcpu->vcpu_id, action, ret_value);

	return ret;
}

bool kvmi_msr_event(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	struct kvmi *ikvm;
	bool ret = true;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return true;

	if (is_event_enabled(vcpu, KVMI_EVENT_MSR))
		ret = __kvmi_msr_event(vcpu, msr);

	kvmi_put(vcpu->kvm);

	return ret;
}

static void __kvmi_xsetbv_event(struct kvm_vcpu *vcpu)
{
	u32 action;

	trace_kvmi_event_xsetbv_send(vcpu->vcpu_id);

	action = kvmi_msg_send_xsetbv(vcpu);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		break;
	default:
		handle_common_event_actions(vcpu, action);
	}

	trace_kvmi_event_xsetbv_recv(vcpu->vcpu_id, action);
}

void kvmi_xsetbv_event(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return;

	if (is_event_enabled(vcpu, KVMI_EVENT_XSETBV))
		__kvmi_xsetbv_event(vcpu);

	kvmi_put(vcpu->kvm);
}

static u64 get_next_rip(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

	if (ivcpu->have_delayed_regs)
		return ivcpu->delayed_regs.rip;
	else
		return kvm_rip_read(vcpu);
}

static void __kvmi_breakpoint_event(struct kvm_vcpu *vcpu, u64 gva)
{
	u32 action;
	u64 gpa;
	u64 old_rip;

	gpa = kvm_mmu_gva_to_gpa_system(vcpu, gva, NULL);
	old_rip = kvm_rip_read(vcpu);

	trace_kvmi_event_bp_send(vcpu->vcpu_id, gpa, old_rip);

	action = kvmi_msg_send_bp(vcpu, gpa);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		kvm_arch_queue_bp(vcpu);
		break;
	case KVMI_EVENT_ACTION_RETRY:
		/* rip was most likely adjusted past the INT 3 instruction */
		break;
	default:
		handle_common_event_actions(vcpu, action);
	}

	trace_kvmi_event_bp_recv(vcpu->vcpu_id, action, get_next_rip(vcpu));
}

bool kvmi_breakpoint_event(struct kvm_vcpu *vcpu, u64 gva)
{
	struct kvmi *ikvm;
	bool ret = false;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return true;

	if (is_event_enabled(vcpu, KVMI_EVENT_BREAKPOINT))
		__kvmi_breakpoint_event(vcpu, gva);
	else
		ret = true;

	kvmi_put(vcpu->kvm);

	return ret;
}
EXPORT_SYMBOL(kvmi_breakpoint_event);

#define KVM_HC_XEN_HVM_OP_GUEST_REQUEST_VM_EVENT 24
static bool kvmi_is_agent_hypercall(struct kvm_vcpu *vcpu)
{
	unsigned long subfunc1, subfunc2;
	bool longmode = is_64_bit_mode(vcpu);

	if (longmode) {
		subfunc1 = kvm_register_read(vcpu, VCPU_REGS_RDI);
		subfunc2 = kvm_register_read(vcpu, VCPU_REGS_RSI);
	} else {
		subfunc1 = kvm_register_read(vcpu, VCPU_REGS_RBX);
		subfunc1 &= 0xFFFFFFFF;
		subfunc2 = kvm_register_read(vcpu, VCPU_REGS_RCX);
		subfunc2 &= 0xFFFFFFFF;
	}

	return (subfunc1 == KVM_HC_XEN_HVM_OP_GUEST_REQUEST_VM_EVENT
	     && subfunc2 == 0);
}

static void __kvmi_hypercall_event(struct kvm_vcpu *vcpu)
{
	u32 action;

	trace_kvmi_event_hc_send(vcpu->vcpu_id);

	action = kvmi_msg_send_hypercall(vcpu);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		break;
	default:
		handle_common_event_actions(vcpu, action);
	}

	trace_kvmi_event_hc_recv(vcpu->vcpu_id, action);
}

bool kvmi_hypercall_event(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm;
	bool ret = false;

	if (!kvmi_is_agent_hypercall(vcpu))
		return ret;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return ret;

	if (is_event_enabled(vcpu, KVMI_EVENT_HYPERCALL)) {
		__kvmi_hypercall_event(vcpu);
		ret = true;
	}

	kvmi_put(vcpu->kvm);

	return ret;
}

void kvmi_init_emulate(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return;

	IVCPU(vcpu)->rep_complete = false;
	IVCPU(vcpu)->effective_rep_complete = false;

	kvmi_put(vcpu->kvm);
}
EXPORT_SYMBOL(kvmi_init_emulate);

/*
 * If the user has requested that events triggered by repetitive
 * instructions be suppressed after the first cycle, then this
 * function will effectively activate it. This ensures that we don't
 * prematurely suppress potential events (second or later) triggerd
 * by an instruction during a single pass.
 */
void kvmi_activate_rep_complete(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return;

	IVCPU(vcpu)->effective_rep_complete = IVCPU(vcpu)->rep_complete;

	kvmi_put(vcpu->kvm);
}
EXPORT_SYMBOL(kvmi_activate_rep_complete);

static bool kvmi_page_fault_event(struct kvm_vcpu *vcpu, unsigned long gpa,
				    unsigned long gva, u8 access)
{
	struct kvmi_vcpu *ivcpu;
	bool singlestep;
	u32 ctx_size;
	u32 action;
	bool ret = false;

	if (!kvm_spt_fault(vcpu))
		/* We are only interested in EPT/NPT violations */
		return true;

	ivcpu = IVCPU(vcpu);
	ctx_size = sizeof(ivcpu->ctx_data);

	if (ivcpu->effective_rep_complete)
		return true;

	trace_kvmi_event_pf_send(vcpu->vcpu_id, gpa, gva, access,
		kvm_rip_read(vcpu));

	action = kvmi_msg_send_pf(vcpu, gpa, gva, access, &singlestep,
		&ivcpu->rep_complete, ivcpu->ctx_data, &ctx_size);

	if (ivcpu->ctx_pos != ivcpu->ctx_size)
		kvmi_err(IKVM(vcpu->kvm), "Losing %d custom bytes",
			 ivcpu->ctx_size - ivcpu->ctx_pos);

	ivcpu->ctx_pos = ivcpu->ctx_size = 0;

	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		ivcpu->ctx_pos = 0;
		ivcpu->ctx_size = ctx_size;
		ret = true;
		break;
	case KVMI_EVENT_ACTION_RETRY:
		if (singlestep && !kvmi_start_ss(vcpu, gpa, access))
			ret = true;
		break;
	default:
		handle_common_event_actions(vcpu, action);
	}

	trace_kvmi_event_pf_recv(vcpu->vcpu_id, action, get_next_rip(vcpu),
		ctx_size, singlestep, ret);

	return ret;
}

bool __kvmi_lost_exception(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

	ivcpu->exception.injected = false;

	if (vcpu->arch.exception.injected &&
		vcpu->arch.exception.nr == ivcpu->exception.nr &&
		vcpu->arch.exception.error_code == ivcpu->exception.error_code)
		return false;

	return true;
}

bool kvmi_lost_exception(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm;
	bool ret = false;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return false;

	if (IVCPU(vcpu)->exception.injected)
		ret = __kvmi_lost_exception(vcpu);

	kvmi_put(vcpu->kvm);

	return ret;
}

static void __kvmi_trap_event(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	u32 vector, type, err;
	u32 action;

	if (vcpu->arch.exception.injected) {
		vector = vcpu->arch.exception.nr;
		err = vcpu->arch.exception.error_code;

		if (kvm_exception_is_soft(vector))
			type = INTR_TYPE_SOFT_EXCEPTION;
		else
			type = INTR_TYPE_HARD_EXCEPTION;
	} else if (vcpu->arch.interrupt.injected) {
		vector = vcpu->arch.interrupt.nr;
		err = 0;

		if (vcpu->arch.interrupt.soft)
			type = INTR_TYPE_SOFT_INTR;
		else
			type = INTR_TYPE_EXT_INTR;
	} else {
		vector = 0;
		type = 0;
		err = 0;
	}

	trace_kvmi_event_trap_send(vcpu->vcpu_id, vector, ivcpu->exception.nr,
		err, ivcpu->exception.error_code, vcpu->arch.cr2);

	action = kvmi_msg_send_trap(vcpu, vector, type, err, vcpu->arch.cr2);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		break;
	default:
		handle_common_event_actions(vcpu, action);
	}

	trace_kvmi_event_trap_recv(vcpu->vcpu_id, action);
}

void kvmi_trap_event(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return;

	if (is_event_enabled(vcpu, KVMI_EVENT_TRAP))
		__kvmi_trap_event(vcpu);

	kvmi_put(vcpu->kvm);
}

static bool __kvmi_descriptor_event(struct kvm_vcpu *vcpu, u32 info,
	unsigned long exit_qualification,
	unsigned char descriptor, unsigned char write)
{
	u32 action;
	bool ret = false;

	trace_kvmi_event_desc_send(vcpu->vcpu_id, info, exit_qualification,
		descriptor, write);

	action = kvmi_msg_send_descriptor(vcpu, info, exit_qualification,
		descriptor, write);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		ret = true;
		break;
	default:
		handle_common_event_actions(vcpu, action);
	}

	trace_kvmi_event_desc_recv(vcpu->vcpu_id, action);

	return ret;
}

bool kvmi_descriptor_event(struct kvm_vcpu *vcpu, u32 info,
	unsigned long exit_qualification,
	unsigned char descriptor, unsigned char write)
{
	struct kvmi *ikvm;
	bool ret = true;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return true;

	if (is_event_enabled(vcpu, KVMI_EVENT_DESCRIPTOR))
		ret = __kvmi_descriptor_event(vcpu, info, exit_qualification,
					      descriptor, write);

	kvmi_put(vcpu->kvm);

	return ret;
}
EXPORT_SYMBOL(kvmi_descriptor_event);

static bool __kvmi_create_vcpu_event(struct kvm_vcpu *vcpu)
{
	u32 action;
	bool ret = false;

	trace_kvmi_event_create_vcpu_send(vcpu->vcpu_id);

	action = kvmi_msg_send_create_vcpu(vcpu);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		ret = true;
		break;
	default:
		handle_common_event_actions(vcpu, action);
	}

	trace_kvmi_event_create_vcpu_recv(vcpu->vcpu_id, action);

	return ret;
}

static bool kvmi_create_vcpu_event(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm;
	bool ret = true;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return true;

	if (test_bit(KVMI_EVENT_CREATE_VCPU, ikvm->vm_ev_mask))
		ret = __kvmi_create_vcpu_event(vcpu);

	kvmi_put(vcpu->kvm);

	return ret;
}

static bool __kvmi_pause_vcpu_event(struct kvm_vcpu *vcpu)
{
	u32 action;
	bool ret = false;

	trace_kvmi_event_pause_vcpu_send(vcpu->vcpu_id);

	action = kvmi_msg_send_pause_vcpu(vcpu);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		ret = true;
		break;
	default:
		handle_common_event_actions(vcpu, action);
	}

	trace_kvmi_event_pause_vcpu_recv(vcpu->vcpu_id, action);

	return ret;
}

static bool kvmi_pause_vcpu_event(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm;
	bool ret = true;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return true;

	ret = __kvmi_pause_vcpu_event(vcpu);

	kvmi_put(vcpu->kvm);

	return ret;
}

bool kvmi_monitored_msr(struct kvm_vcpu *vcpu, u32 msr)
{
	struct kvmi *ikvm;
	bool ret = false;

	if (!vcpu)
		return false;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return false;

	if (test_msr_mask(vcpu, msr)) {
		kvmi_warn_once(ikvm,
			       "Trying to disable write interception for MSR %x\n",
				msr);
		ret = true;
	}

	kvmi_put(vcpu->kvm);

	return ret;
}
EXPORT_SYMBOL(kvmi_monitored_msr);

void kvmi_run_jobs(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvmi_job *job;

	while ((job = kvmi_pull_job(ivcpu))) {
		job->fct(vcpu, job->ctx);
		kfree(job);
	}
}

static bool need_to_wait_for_ss(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvmi *ikvm = IKVM(vcpu->kvm);

	return atomic_read(&ikvm->ss_active) && !ivcpu->ss_owner;
}

static bool need_to_wait(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

	return ivcpu->reply_waiting || need_to_wait_for_ss(vcpu);
}

static bool done_waiting(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

	if (!need_to_wait(vcpu))
		return true;

	return !list_empty(&ivcpu->job_list);
}

static void kvmi_job_wait(struct kvm_vcpu *vcpu, void *ctx)
{
	struct swait_queue_head *wq = kvm_arch_vcpu_wq(vcpu);
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	int err;

	err = swait_event_killable(*wq, done_waiting(vcpu));

	if (err)
		ivcpu->killed = true;
}

int kvmi_run_jobs_and_wait(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	int err = 0;

	for (;;) {
		kvmi_run_jobs(vcpu);

		if (ivcpu->killed) {
			err = -1;
			break;
		}

		if (!need_to_wait(vcpu))
			break;

		kvmi_add_job(vcpu, kvmi_job_wait, NULL);
	}

	return err;
}

/* This is called from vcpu_enter_guest() */
void kvmi_handle_requests(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvmi *ikvm;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return;

	for (;;) {
		int err = kvmi_run_jobs_and_wait(vcpu);

		if (err || !ivcpu->pause_requests)
			break;

		ivcpu->pause_requests--;
		kvmi_pause_vcpu_event(vcpu);
	}

	kvmi_put(vcpu->kvm);
}

void kvmi_post_reply(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

	if (ivcpu->have_delayed_regs) {
		kvm_arch_vcpu_set_regs(vcpu, &ivcpu->delayed_regs);
		ivcpu->have_delayed_regs = false;
	}
}

int kvmi_cmd_get_cpuid(struct kvm_vcpu *vcpu, u32 function, u32 index,
	u32 *eax, u32 *ebx, u32 *ecx, u32 *edx)
{
	struct kvm_cpuid_entry2 *e;

	e = kvm_find_cpuid_entry(vcpu, function, index);
	if (!e)
		return -KVM_ENOENT;

	*eax = e->eax;
	*ebx = e->ebx;
	*ecx = e->ecx;
	*edx = e->edx;

	return 0;
}

int kvmi_cmd_get_guest_info(struct kvm_vcpu *vcpu, u32 *vcpu_cnt, u64 *tsc)
{
	*vcpu_cnt = atomic_read(&vcpu->kvm->online_vcpus);

	if (kvm_has_tsc_control)
		*tsc = 1000ul * vcpu->arch.virtual_tsc_khz;
	else
		*tsc = 0;

	return 0;
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

int kvmi_cmd_get_registers(struct kvm_vcpu *vcpu, u32 *mode,
	struct kvm_regs *regs,
	struct kvm_sregs *sregs, struct kvm_msrs *msrs)
{
	struct kvm_msr_entry *msr = msrs->entries;
	struct kvm_msr_entry *end = msrs->entries + msrs->nmsrs;

	kvm_arch_vcpu_get_regs(vcpu, regs);
	kvm_arch_vcpu_get_sregs(vcpu, sregs);
	*mode = kvmi_vcpu_mode(vcpu, sregs);

	for (; msr < end; msr++) {
		struct msr_data m = {
			.index = msr->index,
			.host_initiated = true
		};
		int err = kvm_get_msr(vcpu, &m);

		if (err)
			return -KVM_EINVAL;

		msr->data = m.data;
	}

	return 0;
}

int kvmi_cmd_set_registers(struct kvm_vcpu *vcpu, const struct kvm_regs *regs)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

	if (ivcpu->reply_waiting) {
		/* defer set registers until we get the reply */
		memcpy(&ivcpu->delayed_regs, regs, sizeof(ivcpu->delayed_regs));
		ivcpu->have_delayed_regs = true;
	} else {
		kvmi_err(IKVM(vcpu->kvm), "Dropped KVMI_SET_REGISTERS\n");
	}

	return 0;
}

int kvmi_cmd_get_page_access(struct kvm_vcpu *vcpu, u64 gpa, u8 *access)
{
	struct kvmi_mem_access *m;
	gfn_t gfn = gpa_to_gfn(gpa);

	m = kvmi_get_gfn_access(IKVM(vcpu->kvm), gfn);

	*access = m ? m->access : full_access;

	return 0;
}

int kvmi_cmd_set_page_access(struct kvm_vcpu *vcpu, u64 gpa, u8 access)
{
	gfn_t gfn = gpa_to_gfn(gpa);

	return kvmi_set_gfn_access(vcpu->kvm, gfn, access);
}

static bool is_vector_valid(u8 vector)
{
	return true;
}

static bool is_gva_valid(struct kvm_vcpu *vcpu, u64 gva)
{
	return true;
}

int kvmi_cmd_inject_exception(struct kvm_vcpu *vcpu, u8 vector,
	bool error_code_valid, u16 error_code, u64 address)
{
	struct x86_exception e = {
		.vector = vector,
		.error_code_valid = error_code_valid,
		.error_code = error_code,
		.address = address,
	};

	trace_kvmi_cmd_inject_exception(vcpu, &e);

	if (!(is_vector_valid(vector) && is_gva_valid(vcpu, address)))
		return -KVM_EINVAL;

	if (e.vector == PF_VECTOR)
		kvm_inject_page_fault(vcpu, &e);
	else if (e.error_code_valid)
		kvm_queue_exception_e(vcpu, e.vector, e.error_code);
	else
		kvm_queue_exception(vcpu, e.vector);

	if (IVCPU(vcpu)->exception.injected)
		kvmi_err(IKVM(vcpu->kvm), "Override exception\n");

	IVCPU(vcpu)->exception.injected = true;
	IVCPU(vcpu)->exception.nr = vector;
	IVCPU(vcpu)->exception.error_code = error_code_valid ? error_code : 0;

	return 0;
}

unsigned long gfn_to_hva_safe(struct kvm *kvm, gfn_t gfn)
{
	unsigned long hva;
	int srcu_idx;

	/* TODO: is this sufficient for a slots reader ??? */
	srcu_idx = srcu_read_lock(&kvm->srcu);
	hva = gfn_to_hva(kvm, gfn);
	srcu_read_unlock(&kvm->srcu, srcu_idx);

	return hva;
}

static long get_user_pages_remote_unlocked(struct mm_struct *mm,
	unsigned long start,
	unsigned long nr_pages,
	unsigned int gup_flags,
	struct page **pages)
{
	long ret;
	struct task_struct *tsk = NULL;
	struct vm_area_struct **vmas = NULL;
	int locked = 1;

	down_read(&mm->mmap_sem);
	ret = get_user_pages_remote(tsk, mm, start, nr_pages, gup_flags,
		pages, vmas, &locked);
	if (locked)
		up_read(&mm->mmap_sem);
	return ret;
}

int kvmi_cmd_read_physical(struct kvm *kvm, u64 gpa, u64 size, int(*send)(
	struct kvmi *, const struct kvmi_msg_hdr *,
	int err, const void *buf, size_t),
	const struct kvmi_msg_hdr *ctx)
{
	int err, ec;
	unsigned long hva;
	struct page *page = NULL;
	void *ptr_page = NULL, *ptr = NULL;
	size_t ptr_size = 0;
	struct kvm_vcpu *vcpu;

	ec = get_first_vcpu(kvm, &vcpu);

	if (ec)
		goto out;

	hva = gfn_to_hva_safe(kvm, gpa_to_gfn(gpa));

	if (kvm_is_error_hva(hva)) {
		ec = -KVM_EINVAL;
		goto out;
	}

	if (get_user_pages_remote_unlocked(kvm->mm, hva, 1, 0, &page) != 1) {
		ec = -KVM_EINVAL;
		goto out;
	}

	ptr_page = kmap_atomic(page);

	ptr = ptr_page + (gpa & ~PAGE_MASK);
	ptr_size = size;

out:
	err = send(IKVM(kvm), ctx, ec, ptr, ptr_size);

	if (ptr_page)
		kunmap_atomic(ptr_page);
	if (page)
		put_page(page);
	return err;
}

int kvmi_cmd_write_physical(struct kvm *kvm, u64 gpa, u64 size, const void *buf)
{
	int err;
	unsigned long hva;
	struct page *page;
	void *ptr;
	struct kvm_vcpu *vcpu;

	err = get_first_vcpu(kvm, &vcpu);

	if (err)
		return err;

	hva = gfn_to_hva_safe(kvm, gpa_to_gfn(gpa));

	if (kvm_is_error_hva(hva))
		return -KVM_EINVAL;

	if (get_user_pages_remote_unlocked(kvm->mm, hva, 1, FOLL_WRITE,
		&page) != 1)
		return -KVM_EINVAL;

	ptr = kmap_atomic(page);

	memcpy(ptr + (gpa & ~PAGE_MASK), buf, size);

	kunmap_atomic(ptr);
	put_page(page);

	return 0;
}

int kvmi_cmd_alloc_token(struct kvm *kvm, struct kvmi_map_mem_token *token)
{
	return kvmi_mem_generate_token(kvm, token);
}

int kvmi_cmd_control_events(struct kvm_vcpu *vcpu, unsigned long event_mask)
{
	return kvmi_control_events(vcpu, event_mask);
}

int kvmi_cmd_control_vm_events(struct kvmi *ikvm, unsigned long event_mask)
{
	bitmap_copy(ikvm->vm_ev_mask, &event_mask, KVMI_NUM_EVENTS);

	return 0;
}

int kvmi_cmd_control_cr(struct kvm_vcpu *vcpu, bool enable, u32 cr)
{
	switch (cr) {
	case 0:
	case 3:
	case 4:
		if (enable)
			set_bit(cr, IVCPU(vcpu)->cr_mask);
		else
			clear_bit(cr, IVCPU(vcpu)->cr_mask);
		return 0;

	default:
		return -KVM_EINVAL;
	}
}

int kvmi_cmd_control_msr(struct kvm_vcpu *vcpu, bool enable, u32 msr)
{
	int err;

	err = msr_control(vcpu, msr, enable);

	if (!err && enable)
		kvm_arch_msr_intercept(vcpu, msr, enable);

	return err;
}

static void kvmi_job_pause(struct kvm_vcpu *vcpu, void *ctx)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

	/*
	 * TODO: every kvmi_cmd_pause_all_vcpus() will inform
	 * the introspection tool that this vCPU will send
	 * one more pause event. This isn't true
	 * if an integer overflow happens.
	 */

	ivcpu->pause_requests++;

	if (unlikely(ivcpu->pause_requests == UINT_MAX))
		kvmi_warn_once(IKVM(vcpu->kvm), "Too many pause requests");
}

int kvmi_cmd_pause_all_vcpus(struct kvm *kvm, u32 *vcpu_count)
{
	int i;
	struct kvm_vcpu *vcpu;

	kvm_for_each_vcpu(i, vcpu, kvm)
		kvmi_add_job(vcpu, kvmi_job_pause, NULL);

	*vcpu_count = i;

	return 0;
}

static void kvmi_kick_all_vcpus(struct kvm_vcpu *me, int req)
{
	struct kvm_vcpu *vcpu;
	int i;

	kvm_for_each_vcpu(i, vcpu, me->kvm)
		if (vcpu != me) {
			if (req)
				kvm_make_request(req, vcpu);
			kvm_vcpu_kick(vcpu);
		}
}

void kvmi_stop_ss(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvm *kvm = vcpu->kvm;
	struct kvmi *ikvm;
	int i;

	ikvm = kvmi_get(kvm);
	if (!ikvm)
		return;

	if (unlikely(!ivcpu->ss_owner)) {
		kvmi_warn(ikvm, "%s", __func__);
		WARN_ON(1);
		goto out;
	}

	for (i = ikvm->ss_level; i--;)
		kvmi_set_gfn_access(kvm,
				    ikvm->ss_context[i].gfn,
				    ikvm->ss_context[i].old_access);

	ikvm->ss_level = 0;

	kvm_set_mtf(vcpu, false);
	/* The blocking by STI is cleared after the guest
	 * executes one instruction or incurs an exception.
	 * However we migh stop the SS before entering to guest,
	 * so be sure we are clearing the STI blocking.
	 */
	kvm_set_interrupt_shadow(vcpu, 0);

	atomic_set(&ikvm->ss_active, false);
	/*
	 * Make ss_active update visible
	 * before resuming all the other vCPUs.
	 */
	smp_mb__after_atomic();
	kvmi_kick_all_vcpus(vcpu, 0);

	ivcpu->ss_owner = false;

out:
	trace_kvmi_stop_ss(vcpu->vcpu_id);
	kvmi_put(kvm);
}
EXPORT_SYMBOL(kvmi_stop_ss);

static bool kvmi_acquire_ss(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvmi *ikvm = IKVM(vcpu->kvm);

	if (ivcpu->ss_owner)
		return true;

	if (atomic_cmpxchg(&ikvm->ss_active, false, true) != false)
		return false;

	kvmi_kick_all_vcpus(vcpu, KVM_REQ_INTROSPECTION);

	ivcpu->ss_owner = true;

	return true;
}

static bool kvmi_run_ss(struct kvm_vcpu *vcpu, unsigned long gpa, u8 access)
{
	struct kvmi *ikvm = IKVM(vcpu->kvm);
	struct kvmi_mem_access *m;
	u8 old_access, new_access;
	gfn_t gfn = gpa_to_gfn(gpa);

	trace_kvmi_run_ss(vcpu, gpa, access, ikvm->ss_level);

	kvm_set_mtf(vcpu, true);

	/* Set block by STI only if the RFLAGS.IF = 1.
	 * Blocking by both STI and MOV/POP SS is not possible.
	 */
	if (kvm_arch_interrupt_allowed(vcpu))
		kvm_set_interrupt_shadow(vcpu, KVM_X86_SHADOW_INT_STI);

	m = kvmi_get_gfn_access(IKVM(vcpu->kvm), gfn);
	/* likely was removed from radix tree due to rwx */
	if (!m)
		return true;
	old_access = m->access;

	if (ikvm->ss_level == SINGLE_STEP_MAX_DEPTH - 1) {
		kvmi_err(ikvm, "Single step limit reached\n");
		return false;
	}

	ikvm->ss_context[ikvm->ss_level].gfn = gfn;
	ikvm->ss_context[ikvm->ss_level].old_access = old_access;
	ikvm->ss_level++;

	new_access = old_access | access;

	/*
	 * An SPTE entry with just the -wx bits set can trigger a
	 * misconfiguration error from the hardware, as it's the case
	 * for x86 where this access mode is used to mark I/O memory.
	 * Thus, we make sure that -wx accesses are translated to rwx.
	 */
	if ((new_access & (KVMI_PAGE_ACCESS_W | KVMI_PAGE_ACCESS_X)) ==
	    (KVMI_PAGE_ACCESS_W | KVMI_PAGE_ACCESS_X))
		new_access |= KVMI_PAGE_ACCESS_R;

	kvmi_set_gfn_access(vcpu->kvm, gfn, new_access);

	return true;
}

static bool kvmi_start_ss(struct kvm_vcpu *vcpu, u64 gpa, u8 access)
{
	bool ret = false;

	while (!kvmi_acquire_ss(vcpu)) {
		int err = kvmi_run_jobs_and_wait(vcpu);

		if (err)
			goto out;
	}

	if (kvmi_run_ss(vcpu, gpa, access))
		ret = true;
	else
		kvmi_stop_ss(vcpu);

out:
	return ret;
}

bool kvmi_vcpu_enabled_ss(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvmi *ikvm;
	bool ret;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return false;

	ret = ivcpu->ss_owner;

	kvmi_put(vcpu->kvm);

	return ret;
}
EXPORT_SYMBOL(kvmi_vcpu_enabled_ss);

bool kvmi_update_ad_flags(struct kvm_vcpu *vcpu)
{
	struct x86_exception exception = {};
	struct kvmi *ikvm;
	bool ret = false;
	gva_t gva;
	gpa_t gpa;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return false;

	gva = kvm_mmu_fault_gla(vcpu);

	if (gva == ~0ull) {
		kvmi_warn_once(ikvm, "%s: cannot perform translation\n",
			       __func__);
		goto out;
	}

	gpa = kvm_mmu_gva_to_gpa_write(vcpu, gva, NULL);
	if (gpa == UNMAPPED_GVA)
		gpa = kvm_mmu_gva_to_gpa_read(vcpu, gva, &exception);

	ret = (gpa != UNMAPPED_GVA);

	if (unlikely(!ret))
		kvmi_err(ikvm, "translation failed: vector: %u, error_code: %hu, address: 0x%016llx\n",
			 (unsigned int)exception.vector, exception.error_code,
			 exception.address);

out:
	kvmi_put(vcpu->kvm);

	return ret;
}

static void kvmi_job_abort(struct kvm_vcpu *vcpu, void *ctx)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

	ivcpu->pause_requests = 0;
	ivcpu->reply_waiting = false;
}

static void kvmi_abort_events(struct kvm *kvm)
{
	int i;
	struct kvm_vcpu *vcpu;

	kvm_for_each_vcpu(i, vcpu, kvm)
		kvmi_add_job(vcpu, kvmi_job_abort, NULL);
}

int kvmi_notify_unhook(struct kvm *kvm)
{
	struct kvmi *ikvm;
	int err = -ENOENT;

	ikvm = kvmi_get(kvm);
	if (!ikvm)
		goto out;

	if (test_bit(KVMI_EVENT_UNHOOK, ikvm->vm_ev_mask))
		err = kvmi_msg_send_unhook(ikvm);
	else
		err = -EPERM;

	kvmi_put(kvm);

out:
	return err;
}
