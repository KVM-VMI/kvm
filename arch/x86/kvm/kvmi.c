// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection - x86
 *
 * Copyright (C) 2019 Bitdefender S.R.L.
 */
#include "x86.h"
#include "../../../virt/kvm/kvmi_int.h"

/*
 * TODO: this can be done from userspace.
 *   - all these registers are sent with struct kvmi_event_arch
 *   - userspace can request MSR_EFER with KVMI_GET_REGISTERS
 */
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

static void kvmi_get_msrs(struct kvm_vcpu *vcpu, struct kvmi_event_arch *event)
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

void kvmi_arch_setup_event(struct kvm_vcpu *vcpu, struct kvmi_event *ev)
{
	struct kvmi_event_arch *event = &ev->arch;

	kvm_arch_vcpu_get_regs(vcpu, &event->regs);
	kvm_arch_vcpu_get_sregs(vcpu, &event->sregs);
	ev->arch.mode = kvmi_vcpu_mode(vcpu, &event->sregs);
	kvmi_get_msrs(vcpu, event);
}

bool kvmi_arch_pf_event(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
			u8 access)
{
	struct kvmi_vcpu *ivcpu;
	u32 ctx_size;
	u64 ctx_addr;
	u32 action;
	bool singlestep_ignored;
	bool ret = false;

	if (!kvm_spt_fault(vcpu))
		/* We are only interested in EPT/NPT violations */
		return true;

	ivcpu = IVCPU(vcpu);
	ctx_size = sizeof(ivcpu->ctx_data);

	if (ivcpu->effective_rep_complete)
		return true;

	action = kvmi_msg_send_pf(vcpu, gpa, gva, access, &singlestep_ignored,
				  &ivcpu->rep_complete, &ctx_addr,
				  ivcpu->ctx_data, &ctx_size);

	ivcpu->ctx_size = 0;
	ivcpu->ctx_addr = 0;

	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		ivcpu->ctx_size = ctx_size;
		ivcpu->ctx_addr = ctx_addr;
		ret = true;
		break;
	case KVMI_EVENT_ACTION_RETRY:
		break;
	default:
		kvmi_handle_common_event_actions(vcpu, action, "PF");
	}

	return ret;
}

int kvmi_arch_cmd_get_vcpu_info(struct kvm_vcpu *vcpu,
				struct kvmi_get_vcpu_info_reply *rpl)
{
	if (kvm_has_tsc_control)
		rpl->tsc_speed = 1000ul * vcpu->arch.virtual_tsc_khz;
	else
		rpl->tsc_speed = 0;

	return 0;
}

static const struct {
	unsigned int allow_bit;
	enum kvm_page_track_mode track_mode;
} track_modes[] = {
	{ KVMI_PAGE_ACCESS_R, KVM_PAGE_TRACK_PREREAD },
	{ KVMI_PAGE_ACCESS_W, KVM_PAGE_TRACK_PREWRITE },
	{ KVMI_PAGE_ACCESS_X, KVM_PAGE_TRACK_PREEXEC },
};

void kvmi_arch_update_page_tracking(struct kvm *kvm,
				    struct kvm_memory_slot *slot,
				    struct kvmi_mem_access *m)
{
	struct kvmi_arch_mem_access *arch = &m->arch;
	int i;

	if (!slot) {
		slot = gfn_to_memslot(kvm, m->gfn);
		if (!slot)
			return;
	}

	for (i = 0; i < ARRAY_SIZE(track_modes); i++) {
		unsigned int allow_bit = track_modes[i].allow_bit;
		enum kvm_page_track_mode mode = track_modes[i].track_mode;
		bool slot_tracked = test_bit(slot->id, arch->active[mode]);

		if (m->access & allow_bit) {
			if (slot_tracked) {
				kvm_slot_page_track_remove_page(kvm, slot,
								m->gfn, mode);
				clear_bit(slot->id, arch->active[mode]);
			}
		} else if (!slot_tracked) {
			kvm_slot_page_track_add_page(kvm, slot, m->gfn, mode);
			set_bit(slot->id, arch->active[mode]);
		}
	}
}

int kvmi_arch_cmd_get_page_access(struct kvmi *ikvm,
				  const struct kvmi_msg_hdr *msg,
				  const struct kvmi_get_page_access *req,
				  struct kvmi_get_page_access_reply **dest,
				  size_t *dest_size)
{
	struct kvmi_get_page_access_reply *rpl = NULL;
	size_t rpl_size = 0;
	size_t k, n = req->count;
	int ec = 0;

	if (req->padding)
		return -KVM_EINVAL;

	if (msg->size < sizeof(*req) + req->count * sizeof(req->gpa[0]))
		return -KVM_EINVAL;

	if (req->view != 0)	/* TODO */
		return -KVM_EOPNOTSUPP;

	rpl_size = sizeof(*rpl) + sizeof(rpl->access[0]) * n;
	rpl = kvmi_msg_alloc_check(rpl_size);
	if (!rpl)
		return -KVM_ENOMEM;

	for (k = 0; k < n && ec == 0; k++)
		ec = kvmi_cmd_get_page_access(ikvm, req->gpa[k],
					      &rpl->access[k]);

	if (ec) {
		kvmi_msg_free(rpl);
		return ec;
	}

	*dest = rpl;
	*dest_size = rpl_size;

	return 0;
}

int kvmi_arch_cmd_set_page_access(struct kvmi *ikvm,
				  const struct kvmi_msg_hdr *msg,
				  const struct kvmi_set_page_access *req)
{
	const struct kvmi_page_access_entry *entry = req->entries;
	const struct kvmi_page_access_entry *end = req->entries + req->count;
	u8 unknown_bits = ~(KVMI_PAGE_ACCESS_R | KVMI_PAGE_ACCESS_W
			    | KVMI_PAGE_ACCESS_X);
	int ec = 0;

	if (req->padding)
		return -KVM_EINVAL;

	if (msg->size < sizeof(*req) + (end - entry) * sizeof(*entry))
		return -KVM_EINVAL;

	if (req->view != 0)	/* TODO */
		return -KVM_EOPNOTSUPP;

	for (; entry < end; entry++) {
		if ((entry->access & unknown_bits) || entry->padding1
				|| entry->padding2 || entry->padding3)
			ec = -KVM_EINVAL;
		else
			ec = kvmi_cmd_set_page_access(ikvm, entry->gpa,
						      entry->access);
		if (ec)
			kvmi_warn(ikvm, "%s: %llx %x padding %x,%x,%x",
				  __func__, entry->gpa, entry->access,
				  entry->padding1, entry->padding2,
				  entry->padding3);
	}

	return ec;
}

int kvmi_arch_cmd_control_spp(struct kvmi *ikvm)
{
	return kvm_arch_init_spp(ikvm->kvm);
}
