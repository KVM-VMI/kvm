// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection - x86
 *
 * Copyright (C) 2019-2020 Bitdefender S.R.L.
 */

#include "linux/kvm_host.h"
#include "x86.h"
#include "../../../virt/kvm/introspection/kvmi_int.h"

void kvmi_arch_init_vcpu_events_mask(unsigned long *supported)
{
	set_bit(KVMI_VCPU_EVENT_BREAKPOINT, supported);
	set_bit(KVMI_VCPU_EVENT_HYPERCALL, supported);
}

static unsigned int kvmi_vcpu_mode(const struct kvm_vcpu *vcpu,
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

static void kvmi_get_msrs(struct kvm_vcpu *vcpu,
			  struct kvmi_vcpu_event_arch *event)
{
	struct msr_data msr;

	msr.host_initiated = true;

	msr.index = MSR_IA32_SYSENTER_CS;
	kvm_x86_ops.get_msr(vcpu, &msr);
	event->msrs.sysenter_cs = msr.data;

	msr.index = MSR_IA32_SYSENTER_ESP;
	kvm_x86_ops.get_msr(vcpu, &msr);
	event->msrs.sysenter_esp = msr.data;

	msr.index = MSR_IA32_SYSENTER_EIP;
	kvm_x86_ops.get_msr(vcpu, &msr);
	event->msrs.sysenter_eip = msr.data;

	msr.index = MSR_EFER;
	kvm_x86_ops.get_msr(vcpu, &msr);
	event->msrs.efer = msr.data;

	msr.index = MSR_STAR;
	kvm_x86_ops.get_msr(vcpu, &msr);
	event->msrs.star = msr.data;

	msr.index = MSR_LSTAR;
	kvm_x86_ops.get_msr(vcpu, &msr);
	event->msrs.lstar = msr.data;

	msr.index = MSR_CSTAR;
	kvm_x86_ops.get_msr(vcpu, &msr);
	event->msrs.cstar = msr.data;

	msr.index = MSR_IA32_CR_PAT;
	kvm_x86_ops.get_msr(vcpu, &msr);
	event->msrs.pat = msr.data;

	msr.index = MSR_KERNEL_GS_BASE;
	kvm_x86_ops.get_msr(vcpu, &msr);
	event->msrs.shadow_gs = msr.data;
}

void kvmi_arch_setup_vcpu_event(struct kvm_vcpu *vcpu,
				struct kvmi_vcpu_event *ev)
{
	struct kvmi_vcpu_event_arch *event = &ev->arch;

	kvm_arch_vcpu_get_regs(vcpu, &event->regs);
	kvm_arch_vcpu_get_sregs(vcpu, &event->sregs);
	ev->arch.mode = kvmi_vcpu_mode(vcpu, &event->sregs);
	kvmi_get_msrs(vcpu, event);
}

int kvmi_arch_cmd_vcpu_get_registers(struct kvm_vcpu *vcpu,
				const struct kvmi_vcpu_get_registers *req,
				struct kvmi_vcpu_get_registers_reply *rpl)
{
	struct msr_data m = {.host_initiated = true};
	int k, err = 0;

	kvm_arch_vcpu_get_regs(vcpu, &rpl->regs);
	kvm_arch_vcpu_get_sregs(vcpu, &rpl->sregs);
	rpl->mode = kvmi_vcpu_mode(vcpu, &rpl->sregs);
	rpl->msrs.nmsrs = req->nmsrs;

	for (k = 0; k < req->nmsrs && !err; k++) {
		m.index = req->msrs_idx[k];

		err = kvm_x86_ops.get_msr(vcpu, &m);
		if (!err) {
			rpl->msrs.entries[k].index = m.index;
			rpl->msrs.entries[k].data = m.data;
		}
	}

	return err ? -KVM_EINVAL : 0;
}

void kvmi_arch_cmd_vcpu_set_registers(struct kvm_vcpu *vcpu,
				      const struct kvm_regs *regs)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	struct kvm_regs *dest = &vcpui->arch.delayed_regs;

	memcpy(dest, regs, sizeof(*dest));

	vcpui->arch.have_delayed_regs = true;
}

void kvmi_arch_post_reply(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);

	if (!vcpui->arch.have_delayed_regs)
		return;

	kvm_arch_vcpu_set_regs(vcpu, &vcpui->arch.delayed_regs, false);
	vcpui->arch.have_delayed_regs = false;
}

bool kvmi_arch_is_agent_hypercall(struct kvm_vcpu *vcpu)
{
	unsigned long subfunc1, subfunc2;
	bool longmode = is_64_bit_mode(vcpu);

	if (longmode) {
		subfunc1 = kvm_rdi_read(vcpu);
		subfunc2 = kvm_rsi_read(vcpu);
	} else {
		subfunc1 = kvm_rbx_read(vcpu);
		subfunc1 &= 0xFFFFFFFF;
		subfunc2 = kvm_rcx_read(vcpu);
		subfunc2 &= 0xFFFFFFFF;
	}

	return (subfunc1 == KVM_HC_XEN_HVM_OP_GUEST_REQUEST_VM_EVENT
		&& subfunc2 == 0);
}

static int kvmi_control_bp_intercept(struct kvm_vcpu *vcpu, bool enable)
{
	struct kvm_guest_debug dbg = {};
	int err = 0;

	if (enable)
		dbg.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;

	err = kvm_arch_vcpu_set_guest_debug(vcpu, &dbg);

	return err;
}

int kvmi_arch_cmd_control_intercept(struct kvm_vcpu *vcpu,
				    unsigned int event_id, bool enable)
{
	int err = 0;

	switch (event_id) {
	case KVMI_VCPU_EVENT_BREAKPOINT:
		err = kvmi_control_bp_intercept(vcpu, enable);
		break;
	default:
		break;
	}

	return err;
}

void kvmi_arch_breakpoint_event(struct kvm_vcpu *vcpu, u64 gva, u8 insn_len)
{
	u32 action;
	u64 gpa;

	gpa = kvm_mmu_gva_to_gpa_system(vcpu, gva, 0, NULL);

	action = kvmi_msg_send_vcpu_bp(vcpu, gpa, insn_len);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		kvm_queue_exception(vcpu, BP_VECTOR);
		break;
	case KVMI_EVENT_ACTION_RETRY:
		/* rip was most likely adjusted past the INT 3 instruction */
		break;
	default:
		kvmi_handle_common_event_actions(vcpu, action);
	}
}

static void kvmi_arch_restore_interception(struct kvm_vcpu *vcpu)
{
}

bool kvmi_arch_clean_up_interception(struct kvm_vcpu *vcpu)
{
	struct kvmi_interception *arch_vcpui = vcpu->arch.kvmi;

	if (!arch_vcpui)
		return false;

	if (!arch_vcpui->restore_interception)
		return false;

	kvmi_arch_restore_interception(vcpu);

	return true;
}

bool kvmi_arch_vcpu_alloc_interception(struct kvm_vcpu *vcpu)
{
	struct kvmi_interception *arch_vcpui;

	arch_vcpui = kzalloc(sizeof(*arch_vcpui), GFP_KERNEL);
	if (!arch_vcpui)
		return false;

	return true;
}

void kvmi_arch_vcpu_free_interception(struct kvm_vcpu *vcpu)
{
	kfree(vcpu->arch.kvmi);
	WRITE_ONCE(vcpu->arch.kvmi, NULL);
}

bool kvmi_arch_vcpu_introspected(struct kvm_vcpu *vcpu)
{
	return !!READ_ONCE(vcpu->arch.kvmi);
}

void kvmi_arch_request_interception_cleanup(struct kvm_vcpu *vcpu)
{
	struct kvmi_interception *arch_vcpui = READ_ONCE(vcpu->arch.kvmi);

	if (arch_vcpui)
		arch_vcpui->restore_interception = true;
}
