// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection
 *
 * Copyright (C) 2017 Bitdefender S.R.L.
 *
 */
#include <linux/mmu_context.h>
#include <linux/random.h>
#include <uapi/linux/kvmi.h>
#include <uapi/asm/kvmi.h>
#include "../../arch/x86/kvm/x86.h"
#include "../../arch/x86/kvm/mmu.h"
#include <asm/vmx.h>
#include "cpuid.h"
#include "kvmi_int.h"
#include <asm/kvm_page_track.h>

/* TODO: split this into arch-independent and x86 */

#define CREATE_TRACE_POINTS
#include <trace/events/kvmi.h>

struct kvmi_mem_access {
	struct list_head link;
	gfn_t gfn;
	u8 access;
	bool active[KVM_PAGE_TRACK_MAX];
	struct kvm_memory_slot *slot;
};

static void wakeup_events(struct kvm *kvm);
static bool kvmi_page_fault_event(struct kvm_vcpu *vcpu, unsigned long gpa,
			   unsigned long gva, u8 access);

static struct workqueue_struct *wq;

static const u8 full_access = KVMI_PAGE_ACCESS_R |
			      KVMI_PAGE_ACCESS_W | KVMI_PAGE_ACCESS_X;

static const struct {
	unsigned int allow_bit;
	enum kvm_page_track_mode track_mode;
} track_modes[] = {
	{ KVMI_PAGE_ACCESS_R, KVM_PAGE_TRACK_PREREAD },
	{ KVMI_PAGE_ACCESS_W, KVM_PAGE_TRACK_PREWRITE },
	{ KVMI_PAGE_ACCESS_X, KVM_PAGE_TRACK_PREEXEC },
};

void kvmi_make_request(struct kvmi_vcpu *ivcpu, int req)
{
	set_bit(req, &ivcpu->requests);
	/* Make sure the bit is set when the worker wakes up */
	smp_wmb();
	up(&ivcpu->sem_requests);
}

void kvmi_clear_request(struct kvmi_vcpu *ivcpu, int req)
{
	clear_bit(req, &ivcpu->requests);
}

int kvmi_cmd_pause_vcpu(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

	/*
	 * This vcpu is already stopped, executing this command
	 * as a result of the REQ_CMD bit being set
	 * (see kvmi_handle_request).
	 */
	if (ivcpu->pause)
		return -KVM_EBUSY;

	ivcpu->pause = true;

	return 0;
}

static void kvmi_apply_mem_access(struct kvm *kvm,
				  struct kvm_memory_slot *slot,
				  struct kvmi_mem_access *m)
{
	int idx, i;

	if (!slot) {
		slot = gfn_to_memslot(kvm, m->gfn);
		if (!slot)
			return;
	}

	idx = srcu_read_lock(&kvm->srcu);

	spin_lock(&kvm->mmu_lock);

	for (i = 0; i < ARRAY_SIZE(track_modes); i++) {
		unsigned int allow_bit = track_modes[i].allow_bit;
		enum kvm_page_track_mode mode = track_modes[i].track_mode;

		if (m->access & allow_bit) {
			if (m->active[mode] && m->slot == slot) {
				kvm_slot_page_track_remove_page(kvm, slot,
								m->gfn, mode);
				m->active[mode] = false;
				m->slot = NULL;
			}
		} else if (!m->active[mode] || m->slot != slot) {
			kvm_slot_page_track_add_page(kvm, slot, m->gfn, mode);
			m->active[mode] = true;
			m->slot = slot;
		}
	}

	spin_unlock(&kvm->mmu_lock);

	srcu_read_unlock(&kvm->srcu, idx);
}

int kvmi_set_mem_access(struct kvm *kvm, u64 gpa, u8 access)
{
	struct kvmi_mem_access *m;
	struct kvmi_mem_access *__m;
	struct kvmi *ikvm = IKVM(kvm);
	gfn_t gfn = gpa_to_gfn(gpa);

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return -KVM_ENOMEM;

	INIT_LIST_HEAD(&m->link);
	m->gfn = gfn;
	m->access = access;

	mutex_lock(&ikvm->access_tree_lock);
	__m = radix_tree_lookup(&ikvm->access_tree, m->gfn);
	if (__m) {
		__m->access = m->access;
		if (list_empty(&__m->link))
			list_add_tail(&__m->link, &ikvm->access_list);
	} else {
		radix_tree_insert(&ikvm->access_tree, m->gfn, m);
		list_add_tail(&m->link, &ikvm->access_list);
		m = NULL;
	}
	mutex_unlock(&ikvm->access_tree_lock);

	kfree(m);

	return 0;
}

static bool kvmi_test_mem_access(struct kvm *kvm, unsigned long gpa,
				 u8 access)
{
	struct kvmi_mem_access *m;
	struct kvmi *ikvm = IKVM(kvm);

	if (!ikvm)
		return false;

	mutex_lock(&ikvm->access_tree_lock);
	m = radix_tree_lookup(&ikvm->access_tree, gpa_to_gfn(gpa));
	mutex_unlock(&ikvm->access_tree_lock);

	/*
	 * We want to be notified only for violations involving access
	 * bits that we've specifically cleared
	 */
	if (m && ((~m->access) & access))
		return true;

	return false;
}

static struct kvmi_mem_access *
kvmi_get_mem_access_unlocked(struct kvm *kvm, const gfn_t gfn)
{
	return radix_tree_lookup(&IKVM(kvm)->access_tree, gfn);
}

static bool is_introspected(struct kvmi *ikvm)
{
	return (ikvm && ikvm->sock);
}

void kvmi_flush_mem_access(struct kvm *kvm)
{
	struct kvmi *ikvm = IKVM(kvm);

	if (!ikvm)
		return;

	mutex_lock(&ikvm->access_tree_lock);
	while (!list_empty(&ikvm->access_list)) {
		struct kvmi_mem_access *m =
			list_first_entry(&ikvm->access_list,
					 struct kvmi_mem_access, link);

		list_del_init(&m->link);

		kvmi_apply_mem_access(kvm, NULL, m);

		if (m->access == full_access) {
			radix_tree_delete(&ikvm->access_tree, m->gfn);
			kfree(m);
		}
	}
	mutex_unlock(&ikvm->access_tree_lock);
}

static void kvmi_free_mem_access(struct kvm *kvm)
{
	void **slot;
	struct radix_tree_iter iter;
	struct kvmi *ikvm = IKVM(kvm);

	mutex_lock(&ikvm->access_tree_lock);
	radix_tree_for_each_slot(slot, &ikvm->access_tree, &iter, 0) {
		struct kvmi_mem_access *m = *slot;

		m->access = full_access;
		kvmi_apply_mem_access(kvm, NULL, m);

		radix_tree_delete(&ikvm->access_tree, m->gfn);
		kfree(*slot);
	}
	mutex_unlock(&ikvm->access_tree_lock);
}

static unsigned long *msr_mask(struct kvmi *ikvm, unsigned int *msr)
{
	switch (*msr) {
	case 0 ... 0x1fff:
		return ikvm->msr_mask.low;
	case 0xc0000000 ... 0xc0001fff:
		*msr &= 0x1fff;
		return ikvm->msr_mask.high;
	}
	return NULL;
}

static bool test_msr_mask(struct kvmi *ikvm, unsigned int msr)
{
	unsigned long *mask = msr_mask(ikvm, &msr);

	if (!mask)
		return false;
	if (!test_bit(msr, mask))
		return false;

	return true;
}

static int msr_control(struct kvmi *ikvm, unsigned int msr, bool enable)
{
	unsigned long *mask = msr_mask(ikvm, &msr);

	if (!mask)
		return -KVM_EINVAL;
	if (enable)
		set_bit(msr, mask);
	else
		clear_bit(msr, mask);
	return 0;
}

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

static int maybe_delayed_init(void)
{
	if (wq)
		return 0;

	wq = alloc_workqueue("kvmi", WQ_CPU_INTENSIVE, 0);
	if (!wq)
		return -ENOMEM;

	return 0;
}

int kvmi_init(void)
{
	return 0;
}

static void work_cb(struct work_struct *work)
{
	struct kvmi *ikvm = container_of(work, struct kvmi, work);
	struct kvm *kvm = ikvm->kvm;

	while (kvmi_msg_process(ikvm));

	/* We are no longer interested in any kind of events */
	atomic_set(&ikvm->event_mask, 0);

	/* Clean-up for the next kvmi_hook() call */
	ikvm->cr_mask = 0;
	memset(&ikvm->msr_mask, 0, sizeof(ikvm->msr_mask));

	wakeup_events(kvm);

	/* Restore the spte access rights */
	/* Shouldn't wait for reconnection? */
	kvmi_free_mem_access(kvm);

	complete_all(&ikvm->finished);
}

static void __alloc_vcpu_kvmi(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu;

	ivcpu = kzalloc(sizeof(*ivcpu), GFP_KERNEL);

	if (!ivcpu)
		return;

	sema_init(&ivcpu->sem_requests, 0);

	/*
	 * Make sure the ivcpu is initialized
	 * before making it visible.
	 */
	smp_wmb();

	vcpu->kvmi = ivcpu;

	kvmi_make_request(ivcpu, REQ_INIT);
	kvm_make_request(KVM_REQ_INTROSPECTION, vcpu);
}

void kvmi_vcpu_init(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm = IKVM(vcpu->kvm);

	if (is_introspected(ikvm)) {
		mutex_lock(&vcpu->kvm->lock);
		__alloc_vcpu_kvmi(vcpu);
		mutex_unlock(&vcpu->kvm->lock);
	}
}

void kvmi_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	kfree(IVCPU(vcpu));
}

/*
 * When called from outside a page fault handler, this call should
 * return ~0ull
 */
static u64 kvmi_mmu_fault_gla(struct kvm_vcpu *vcpu, gpa_t gpa)
{
	u64 gla;
	u64 gla_val;
	u64 v;

	if (!vcpu->arch.gpa_available)
		return ~0ull;

	gla = kvm_mmu_fault_gla(vcpu);
	if (gla == ~0ull)
		return gla;
	gla_val = gla;

	/* Handle the potential overflow by returning ~0ull */
	if (vcpu->arch.gpa_val > gpa) {
		v = vcpu->arch.gpa_val - gpa;
		if (v > gla)
			gla = ~0ull;
		else
			gla -= v;
	} else {
		v = gpa - vcpu->arch.gpa_val;
		if (v > (U64_MAX - gla))
			gla = ~0ull;
		else
			gla += v;
	}

	return gla;
}

static bool kvmi_track_preread(struct kvm_vcpu *vcpu, gpa_t gpa,
			       u8 *new,
			       int bytes,
			       struct kvm_page_track_notifier_node *node,
			       bool *data_ready)
{
	u64 gla;
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	bool ret = true;

	if (kvm_mmu_nested_guest_page_fault(vcpu))
		return ret;
	gla = kvmi_mmu_fault_gla(vcpu, gpa);
	ret = kvmi_page_fault_event(vcpu, gpa, gla, KVMI_PAGE_ACCESS_R);
	if (ivcpu && ivcpu->ctx_size > 0) {
		int s = min_t(int, bytes, ivcpu->ctx_size);

		memcpy(new, ivcpu->ctx_data, s);
		ivcpu->ctx_size = 0;

		if (*data_ready)
			kvm_err("Override custom data");

		*data_ready = true;
	}

	return ret;
}

static bool kvmi_track_prewrite(struct kvm_vcpu *vcpu, gpa_t gpa,
				const u8 *new,
				int bytes,
				struct kvm_page_track_notifier_node *node)
{
	u64 gla;

	if (kvm_mmu_nested_guest_page_fault(vcpu))
		return true;
	gla = kvmi_mmu_fault_gla(vcpu, gpa);
	return kvmi_page_fault_event(vcpu, gpa, gla, KVMI_PAGE_ACCESS_W);
}

static bool kvmi_track_preexec(struct kvm_vcpu *vcpu, gpa_t gpa,
				struct kvm_page_track_notifier_node *node)
{
	u64 gla;

	if (kvm_mmu_nested_guest_page_fault(vcpu))
		return true;
	gla = kvmi_mmu_fault_gla(vcpu, gpa);

	return kvmi_page_fault_event(vcpu, gpa, gla, KVMI_PAGE_ACCESS_X);
}

static void kvmi_track_create_slot(struct kvm *kvm,
				   struct kvm_memory_slot *slot,
				   unsigned long npages,
				   struct kvm_page_track_notifier_node *node)
{
	struct kvmi *ikvm = IKVM(kvm);
	gfn_t start = slot->base_gfn;
	const gfn_t end = start + npages;

	if (!ikvm)
		return;

	mutex_lock(&ikvm->access_tree_lock);

	while (start < end) {
		struct kvmi_mem_access *m;

		m = kvmi_get_mem_access_unlocked(kvm, start);
		if (m)
			kvmi_apply_mem_access(kvm, slot, m);
		start++;
	}

	mutex_unlock(&ikvm->access_tree_lock);
}

static void kvmi_track_flush_slot(struct kvm *kvm, struct kvm_memory_slot *slot,
				  struct kvm_page_track_notifier_node *node)
{
	struct kvmi *ikvm = IKVM(kvm);
	gfn_t start = slot->base_gfn;
	const gfn_t end = start + slot->npages;

	if (!ikvm)
		return;

	mutex_lock(&ikvm->access_tree_lock);

	while (start < end) {
		struct kvmi_mem_access *m;

		m = kvmi_get_mem_access_unlocked(kvm, start);
		if (m) {
			u8 prev_access = m->access;

			m->access = full_access;
			kvmi_apply_mem_access(kvm, slot, m);
			m->access = prev_access;
		}
		start++;
	}

	mutex_unlock(&ikvm->access_tree_lock);
}

static struct kvm_page_track_notifier_node kptn_node = {
	.track_preread = kvmi_track_preread,
	.track_prewrite = kvmi_track_prewrite,
	.track_preexec = kvmi_track_preexec,
	.track_create_slot = kvmi_track_create_slot,
	.track_flush_slot = kvmi_track_flush_slot
};

static bool __alloc_kvmi(struct kvm *kvm)
{
	struct kvmi *ikvm;

	ikvm = kzalloc(sizeof(*ikvm), GFP_KERNEL);

	if (!ikvm)
		return false;

	INIT_LIST_HEAD(&ikvm->access_list);
	mutex_init(&ikvm->access_tree_lock);
	INIT_RADIX_TREE(&ikvm->access_tree, GFP_KERNEL);
	rwlock_init(&ikvm->sock_lock);
	init_completion(&ikvm->finished);
	INIT_WORK(&ikvm->work, work_cb);

	kvm_page_track_register_notifier(kvm, &kptn_node);

	kvm->kvmi = ikvm;
	ikvm->kvm = kvm; /* work_cb */

	return true;
}

static bool alloc_kvmi(struct kvm *kvm)
{
	bool done;

	mutex_lock(&kvm->lock);
	done = (
		maybe_delayed_init() == 0 &&
		(IKVM(kvm) || __alloc_kvmi(kvm))
	);
	mutex_unlock(&kvm->lock);

	return done;
}

static void alloc_all_kvmi_vcpu(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	int i;

	mutex_lock(&kvm->lock);
	kvm_for_each_vcpu(i, vcpu, kvm)
		if (!IKVM(vcpu))
			__alloc_vcpu_kvmi(vcpu);
	mutex_unlock(&kvm->lock);
}

static bool setup_socket(struct kvm *kvm, struct kvm_introspection *qemu)
{
	struct kvmi *ikvm = IKVM(kvm);

	if (is_introspected(ikvm)) {
		kvm_err("Guest already introspected\n");
		return false;
	}

	if (!kvmi_msg_init(ikvm, qemu->fd))
		return false;

	ikvm->cmd_allow_mask = -1; /* TODO: qemu->commands; */
	ikvm->event_allow_mask = -1; /* TODO: qemu->events; */

	alloc_all_kvmi_vcpu(kvm);
	queue_work(wq, &ikvm->work);

	return true;
}

int kvmi_hook(struct kvm *kvm, struct kvm_introspection *qemu)
{
	kvm_info("Hooking vm with fd: %d\n", qemu->fd);

	if (!alloc_kvmi(kvm) || !setup_socket(kvm, qemu))
		return -EFAULT;

	return 0;
}

void kvmi_destroy_vm(struct kvm *kvm)
{
	struct kvmi *ikvm = IKVM(kvm);

	if (ikvm) {
		kvmi_msg_uninit(ikvm);

		mutex_destroy(&ikvm->access_tree_lock);
		kfree(ikvm);
	}

	kvmi_mem_destroy_vm(kvm);
}

void kvmi_uninit(void)
{
	if (wq) {
		destroy_workqueue(wq);
		wq = NULL;
	}
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
}

static bool is_event_enabled(struct kvm *kvm, int event_bit)
{
	struct kvmi *ikvm = IKVM(kvm);

	return (ikvm && (atomic_read(&ikvm->event_mask) & event_bit));
}

static int kvmi_vcpu_kill(int sig, struct kvm_vcpu *vcpu)
{
	int err = -ESRCH;
	struct pid *pid;
	struct siginfo siginfo[1] = { };

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

	mutex_lock(&kvm->lock);
	kvm_for_each_vcpu(i, vcpu, kvm) {
		kvmi_vcpu_kill(SIGTERM, vcpu);
	}
	mutex_unlock(&kvm->lock);
}

/* TODO: Do we need a return code ? */
static void handle_common_event_actions(struct kvm_vcpu *vcpu, u32 action)
{
	switch (action) {
	case KVMI_EVENT_ACTION_CRASH:
		kvmi_vm_shutdown(vcpu->kvm);
		break;

	default:
		kvm_err("Unsupported event action: %d\n", action);
	}
}

bool kvmi_cr_event(struct kvm_vcpu *vcpu, unsigned int cr,
		   unsigned long old_value, unsigned long *new_value)
{
	struct kvm *kvm = vcpu->kvm;
	u64 ret_value;
	u32 action;
	bool ret = false;

	if (!is_event_enabled(kvm, KVMI_EVENT_CR))
		return true;
	if (!test_bit(cr, &IKVM(kvm)->cr_mask))
		return true;
	if (old_value == *new_value)
		return true;

	action = kvmi_msg_send_cr(vcpu, cr, old_value, *new_value, &ret_value);

	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		*new_value = ret_value;
		ret = true;
		break;
	default:
		handle_common_event_actions(vcpu, action);
	}

	trace_kvmi_event_cr(vcpu->vcpu_id, cr, old_value, *new_value, action);
	return ret;
}

bool kvmi_msr_event(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	struct kvm *kvm = vcpu->kvm;
	u64 ret_value;
	u32 action;
	bool ret = false;
	struct msr_data old_msr = { .host_initiated = true,
				    .index = msr->index };

	if (msr->host_initiated)
		return true;
	if (!is_event_enabled(kvm, KVMI_EVENT_MSR))
		return true;
	if (!test_msr_mask(IKVM(kvm), msr->index))
		return true;
	if (kvm_get_msr(vcpu, &old_msr))
		return true;
	if (old_msr.data == msr->data)
		return true;

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

	trace_kvmi_event_msr(vcpu->vcpu_id, msr->index, old_msr.data, msr->data,
			     action);
	return ret;
}

void kvmi_xsetbv_event(struct kvm_vcpu *vcpu)
{
	u32 action;

	if (!is_event_enabled(vcpu->kvm, KVMI_EVENT_XSETBV))
		return;

	action = kvmi_msg_send_xsetbv(vcpu);

	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		break;
	default:
		handle_common_event_actions(vcpu, action);
	}

	trace_kvmi_event_xsetbv(vcpu->vcpu_id, action);
}

static u64 get_next_rip(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

	if (ivcpu->have_delayed_regs)
		return ivcpu->delayed_regs.rip;
	else
		return kvm_rip_read(vcpu);
}

bool kvmi_breakpoint_event(struct kvm_vcpu *vcpu, u64 gva)
{
	u32 action;
	u64 gpa;
	u64 old_rip;
	bool ret = false;

	if (!is_event_enabled(vcpu->kvm, KVMI_EVENT_BREAKPOINT))
		/* qemu will automatically reinject the breakpoint */
		return true;

	gpa = kvm_mmu_gva_to_gpa_read(vcpu, gva, NULL);

	old_rip = kvm_rip_read(vcpu);

	action = kvmi_msg_send_bp(vcpu, gpa);

	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		ret = true;
		break;
	case KVMI_EVENT_ACTION_RETRY:
		/* rip was most likely adjusted past the INT 3 instruction */
		break;
	default:
		handle_common_event_actions(vcpu, action);
	}

	trace_kvmi_event_breakpoint(vcpu->vcpu_id, gpa, old_rip, action,
				    get_next_rip(vcpu));
	/* qemu will automatically reinject the breakpoint */
	return ret;
}
EXPORT_SYMBOL(kvmi_breakpoint_event);

#define KVM_HC_XEN_HVM_OP_GUEST_REQUEST_VM_EVENT 24
bool kvmi_is_agent_hypercall(struct kvm_vcpu *vcpu)
{
	unsigned long subfunc1, subfunc2;
	bool longmode = is_64_bit_mode(vcpu);
	unsigned long nr = kvm_register_read(vcpu, VCPU_REGS_RAX);

	if (longmode) {
		subfunc1 = kvm_register_read(vcpu, VCPU_REGS_RDI);
		subfunc2 = kvm_register_read(vcpu, VCPU_REGS_RSI);
	} else {
		nr &= 0xFFFFFFFF;
		subfunc1 = kvm_register_read(vcpu, VCPU_REGS_RBX);
		subfunc1 &= 0xFFFFFFFF;
		subfunc2 = kvm_register_read(vcpu, VCPU_REGS_RCX);
		subfunc2 &= 0xFFFFFFFF;
	}

	return (nr == KVM_HC_XEN_HVM_OP
		&& subfunc1 == KVM_HC_XEN_HVM_OP_GUEST_REQUEST_VM_EVENT
		&& subfunc2 == 0);
}

void kvmi_hypercall_event(struct kvm_vcpu *vcpu)
{
	u32 action;

	if (!is_event_enabled(vcpu->kvm, KVMI_EVENT_HYPERCALL)
			|| !kvmi_is_agent_hypercall(vcpu))
		return;

	action = kvmi_msg_send_hypercall(vcpu);

	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		break;
	default:
		handle_common_event_actions(vcpu, action);
	}

	trace_kvmi_event_hypercall(vcpu->vcpu_id, action);
}

bool kvmi_page_fault_event(struct kvm_vcpu *vcpu, unsigned long gpa,
			   unsigned long gva, u8 access)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvmi_vcpu *ivcpu;
	bool trap_access, ret = false;
	u32 ctx_size;
	u64 old_rip;
	u32 action;

	if (!is_event_enabled(kvm, KVMI_EVENT_PAGE_FAULT))
		return true;

	/* Have we shown interest in this page? */
	if (!kvmi_test_mem_access(kvm, gpa, access))
		return true;

	ivcpu = IVCPU(vcpu);
	ctx_size = sizeof(ivcpu->ctx_data);
	old_rip = kvm_rip_read(vcpu);

	action = kvmi_msg_send_pf(vcpu, gpa, gva, access, &trap_access,
				  ivcpu->ctx_data, &ctx_size);

	ivcpu->ctx_size = 0;

	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		ivcpu->ctx_size = ctx_size;
		ret = true;
		break;
	case KVMI_EVENT_ACTION_RETRY:
		break;
	default:
		handle_common_event_actions(vcpu, action);
	}

	/* TODO: trap_access -> don't REPeat the instruction */
	trace_kvmi_event_page_fault(vcpu->vcpu_id, gpa, gva, access, old_rip,
				    action, get_next_rip(vcpu), ctx_size);
	return ret;
}

bool kvmi_lost_exception(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

	if (!ivcpu || !ivcpu->exception.injected)
		return false;

	ivcpu->exception.injected = 0;

	if (!is_event_enabled(vcpu->kvm, KVMI_EVENT_TRAP))
		return false;

	if ((vcpu->arch.exception.injected || vcpu->arch.exception.pending)
		&& vcpu->arch.exception.nr == ivcpu->exception.nr
		&& vcpu->arch.exception.error_code
			== ivcpu->exception.error_code)
		return false;

	return true;
}

void kvmi_trap_event(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	u32 vector, type, err;
	u32 action;

	if (vcpu->arch.exception.pending) {
		vector = vcpu->arch.exception.nr;
		err = vcpu->arch.exception.error_code;

		if (kvm_exception_is_soft(vector))
			type = INTR_TYPE_SOFT_EXCEPTION;
		else
			type = INTR_TYPE_HARD_EXCEPTION;
	} else if (vcpu->arch.interrupt.pending) {
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

	action = kvmi_msg_send_trap(vcpu, vector, type, err, vcpu->arch.cr2);

	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		break;
	default:
		handle_common_event_actions(vcpu, action);
	}

	trace_kvmi_event_trap(vcpu->vcpu_id, vector, ivcpu->exception.nr,
			      err, ivcpu->exception.error_code, vcpu->arch.cr2,
			      action);
}

bool kvmi_descriptor_event(struct kvm_vcpu *vcpu, u32 info,
			   unsigned long exit_qualification,
			   unsigned char descriptor, unsigned char write)
{
	u32 action;
	bool ret = false;

	if (!is_event_enabled(vcpu->kvm, KVMI_EVENT_DESCRIPTOR))
		return true;

	action = kvmi_msg_send_descriptor(vcpu, info, exit_qualification,
					  descriptor, write);

	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		ret = true;
		break;
	default:
		handle_common_event_actions(vcpu, action);
	}

	trace_kvmi_event_descriptor(vcpu->vcpu_id, info, exit_qualification,
				    descriptor, write, action);
	return ret;
}
EXPORT_SYMBOL(kvmi_descriptor_event);

static bool kvmi_create_vcpu_event(struct kvm_vcpu *vcpu)
{
	u32 action;
	bool ret = false;

	if (!is_event_enabled(vcpu->kvm, KVMI_EVENT_CREATE_VCPU))
		return true;

	action = kvmi_msg_send_create_vcpu(vcpu);

	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		ret = true;
		break;
	default:
		handle_common_event_actions(vcpu, action);
	}

	trace_kvmi_event_create_vcpu(vcpu->vcpu_id, action);
	return ret;
}

static bool kvmi_pause_vcpu_event(struct kvm_vcpu *vcpu)
{
	u32 action;
	bool ret = false;

	IVCPU(vcpu)->pause = false;

	action = kvmi_msg_send_pause_vcpu(vcpu);

	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		ret = true;
		break;
	default:
		handle_common_event_actions(vcpu, action);
	}

	trace_kvmi_event_pause_vcpu(vcpu->vcpu_id, action);
	return ret;
}

/* TODO: refactor this function uto avoid recursive calls and the semaphore. */
void kvmi_handle_request(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

	while (ivcpu->ev_rpl_waiting
		|| READ_ONCE(ivcpu->requests)) {

		down(&ivcpu->sem_requests);

		if (test_bit(REQ_INIT, &ivcpu->requests)) {
			/*
			 * kvmi_create_vcpu_event() may call this function
			 * again and won't return unless there is no more work
			 * to be done. The while condition will be evaluated
			 * to false, but we explicitly exit the loop to avoid
			 * surprizing the reader more than we already did.
			 */
			kvmi_clear_request(ivcpu, REQ_INIT);
			if (!kvmi_create_vcpu_event(vcpu))
				break;
		} else if (test_bit(REQ_CMD, &ivcpu->requests)) {
			kvmi_msg_handle_vcpu_cmd(vcpu);
			/* it will clear the REQ_CMD bit */
			if (ivcpu->pause && !ivcpu->ev_rpl_waiting) {
				/* Same warnings as with REQ_INIT. */
				if (!kvmi_pause_vcpu_event(vcpu))
					break;
			}
		} else if (test_bit(REQ_REPLY, &ivcpu->requests)) {
			kvmi_clear_request(ivcpu, REQ_REPLY);
			ivcpu->ev_rpl_waiting = false;
			if (ivcpu->have_delayed_regs) {
				/* TODO: what do we do with the error code? */
				kvm_arch_vcpu_set_regs(vcpu,
							&ivcpu->delayed_regs);
				ivcpu->have_delayed_regs = false;
			}
			if (ivcpu->pause) {
				/* Same warnings as with REQ_INIT. */
				if (!kvmi_pause_vcpu_event(vcpu))
					break;
			}
		} else if (test_bit(REQ_CLOSE, &ivcpu->requests)) {
			kvmi_clear_request(ivcpu, REQ_CLOSE);
			break;
		} else {
			kvm_err("Unexpected request");
		}
	}

	kvmi_flush_mem_access(vcpu->kvm);
	/* TODO: merge with kvmi_set_mem_access() */
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

int kvmi_cmd_get_guest_info(struct kvm_vcpu *vcpu, u16 *vcpu_cnt, u64 *tsc)
{
	/*
	 * Should we switch vcpu_cnt to unsigned int?
	 * If not, we should limit this to max u16 - 1
	 */
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

	kvm_arch_vcpu_ioctl_get_regs(vcpu, regs);
	kvm_arch_vcpu_ioctl_get_sregs(vcpu, sregs);
	*mode = kvmi_vcpu_mode(vcpu, sregs);

	for (; msr < end; msr++) {
		struct msr_data m = { .index = msr->index };
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

	if (ivcpu->ev_rpl_waiting) {
		memcpy(&ivcpu->delayed_regs, regs, sizeof(ivcpu->delayed_regs));
		ivcpu->have_delayed_regs = true;
	} else {
		kvm_err("Drop KVMI_SET_REGISTERS");
	}

	return 0;
}

int kvmi_cmd_get_page_access(struct kvm_vcpu *vcpu, u64 gpa, u8 *access)
{
	struct kvmi *ikvm = IKVM(vcpu->kvm);
	struct kvmi_mem_access *m;

	mutex_lock(&ikvm->access_tree_lock);
	m = kvmi_get_mem_access_unlocked(vcpu->kvm, gpa_to_gfn(gpa));
	*access = m ? m->access : full_access;
	mutex_unlock(&ikvm->access_tree_lock);

	return 0;
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
			      bool error_code_valid, u16 error_code,
			      u64 address)
{
	struct x86_exception e = {
		.vector = vector,
		.error_code_valid = error_code_valid,
		.error_code = error_code,
		.address = address,
	};

	if (!(is_vector_valid(vector) && is_gva_valid(vcpu, address)))
		return -KVM_EINVAL;

	if (e.vector == PF_VECTOR)
		kvm_inject_page_fault(vcpu, &e);
	else if (e.error_code_valid)
		kvm_queue_exception_e(vcpu, e.vector, e.error_code);
	else
		kvm_queue_exception(vcpu, e.vector);

	if (IVCPU(vcpu)->exception.injected)
		kvm_err("Override exception");

	IVCPU(vcpu)->exception.injected = 1;
	IVCPU(vcpu)->exception.nr = e.vector;
	IVCPU(vcpu)->exception.error_code = error_code_valid ? error_code : 0;

	return 0;
}

unsigned long gfn_to_hva_safe(struct kvm *kvm, gfn_t gfn)
{
	unsigned long hva;

	mutex_lock(&kvm->slots_lock);
	hva = gfn_to_hva(kvm, gfn);
	mutex_unlock(&kvm->slots_lock);

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

int kvmi_cmd_read_physical(struct kvm *kvm, u64 gpa, u64 size, int (*send)(
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
	/* create random token */
	get_random_bytes(token, sizeof(*token));

	/* store token in HOST database */
	return kvmi_store_token(kvm, token);
}

int kvmi_cmd_control_events(struct kvm_vcpu *vcpu, u32 events)
{
	int err = 0;

	if (events & ~KVMI_KNOWN_EVENTS)
		return -KVM_EINVAL;

	if (events & KVMI_EVENT_BREAKPOINT) {
		if (!is_event_enabled(vcpu->kvm, KVMI_EVENT_BREAKPOINT)) {
			struct kvm_guest_debug dbg = { };

			dbg.control = KVM_GUESTDBG_ENABLE |
				      KVM_GUESTDBG_USE_SW_BP;

			err = kvm_arch_vcpu_ioctl_set_guest_debug(vcpu, &dbg);
		}
	}

	if (!err)
		atomic_set(&IKVM(vcpu->kvm)->event_mask, events);

	return err;
}

int kvmi_cmd_control_cr(struct kvmi *ikvm, bool enable, u32 cr)
{
	switch (cr) {
	case 0:
	case 3:
	case 4:
		if (enable)
			set_bit(cr, &ikvm->cr_mask);
		else
			clear_bit(cr, &ikvm->cr_mask);
		return 0;

	default:
		return -KVM_EINVAL;
	}
}

int kvmi_cmd_control_msr(struct kvm *kvm, bool enable, u32 msr)
{
	struct kvm_vcpu *vcpu;
	int err;

	err = get_first_vcpu(kvm, &vcpu);
	if (err)
		return err;

	err = msr_control(IKVM(kvm), msr, enable);

	if (!err)
		kvm_arch_msr_intercept(vcpu, msr, enable);

	return err;
}

void wakeup_events(struct kvm *kvm)
{
	int i;
	struct kvm_vcpu *vcpu;

	mutex_lock(&kvm->lock);
	kvm_for_each_vcpu(i, vcpu, kvm)
		kvmi_make_request(IVCPU(vcpu), REQ_CLOSE);
	mutex_unlock(&kvm->lock);
}
