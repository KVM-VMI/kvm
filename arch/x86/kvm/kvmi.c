// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection - x86
 *
 * Copyright (C) 2019 Bitdefender S.R.L.
 */
#include "x86.h"
#include "cpuid.h"
#include <asm/vmx.h>
#include "../../../virt/kvm/kvmi_int.h"

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

int kvmi_arch_cmd_control_msr(struct kvm_vcpu *vcpu,
			      const struct kvmi_control_msr *req)
{
	int err;

	if (req->padding1 || req->padding2)
		return -KVM_EINVAL;

	err = msr_control(vcpu, req->msr, req->enable);

	if (!err && req->enable)
		kvm_arch_msr_intercept(vcpu, req->msr, req->enable);

	return err;
}

static u32 kvmi_send_msr(struct kvm_vcpu *vcpu, u32 msr, u64 old_value,
			 u64 new_value, u64 *ret_value)
{
	struct kvmi_event_msr e = {
		.msr = msr,
		.old_value = old_value,
		.new_value = new_value,
	};
	struct kvmi_event_msr_reply r;
	int err, action;

	err = kvmi_send_event(vcpu, KVMI_EVENT_MSR, &e, sizeof(e),
			      &r, sizeof(r), &action);
	if (err) {
		*ret_value = new_value;
		return KVMI_EVENT_ACTION_CONTINUE;
	}

	*ret_value = r.new_val;
	return action;
}

static bool __kvmi_msr_event(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	struct msr_data old_msr = {
		.host_initiated = true,
		.index = msr->index,
	};
	bool ret = false;
	u64 ret_value;
	u32 action;

	if (!test_msr_mask(vcpu, msr->index))
		return true;
	if (kvm_get_msr(vcpu, &old_msr))
		return true;
	if (old_msr.data == msr->data)
		return true;

	action = kvmi_send_msr(vcpu, msr->index, old_msr.data, msr->data,
			       &ret_value);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		msr->data = ret_value;
		ret = true;
		break;
	default:
		kvmi_handle_common_event_actions(vcpu, action, "MSR");
	}

	return ret;
}

bool kvmi_msr_event(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	struct kvmi *ikvm;
	bool ret = true;

	if (msr->host_initiated)
		return true;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return true;

	if (is_event_enabled(vcpu, KVMI_EVENT_MSR))
		ret = __kvmi_msr_event(vcpu, msr);

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

static void *alloc_get_registers_reply(const struct kvmi_msg_hdr *msg,
				       const struct kvmi_get_registers *req,
				       size_t *rpl_size)
{
	struct kvmi_get_registers_reply *rpl;
	u16 k, n = req->nmsrs;

	*rpl_size = sizeof(*rpl) + sizeof(rpl->msrs.entries[0]) * n;
	rpl = kvmi_msg_alloc_check(*rpl_size);
	if (rpl) {
		rpl->msrs.nmsrs = n;

		for (k = 0; k < n; k++)
			rpl->msrs.entries[k].index = req->msrs_idx[k];
	}

	return rpl;
}

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

static int kvmi_get_registers(struct kvm_vcpu *vcpu, u32 *mode,
			      struct kvm_regs *regs,
			      struct kvm_sregs *sregs,
			      struct kvm_msrs *msrs)
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

int kvmi_arch_cmd_get_registers(struct kvm_vcpu *vcpu,
				const struct kvmi_msg_hdr *msg,
				const struct kvmi_get_registers *req,
				struct kvmi_get_registers_reply **dest,
				size_t *dest_size)
{
	struct kvmi_get_registers_reply *rpl;
	size_t rpl_size = 0;
	int err;

	if (req->padding1 || req->padding2)
		return -KVM_EINVAL;

	if (msg->size < sizeof(struct kvmi_vcpu_hdr)
			+ sizeof(*req) + req->nmsrs * sizeof(req->msrs_idx[0]))
		return -KVM_EINVAL;

	rpl = alloc_get_registers_reply(msg, req, &rpl_size);
	if (!rpl)
		return -KVM_ENOMEM;

	err = kvmi_get_registers(vcpu, &rpl->mode, &rpl->regs,
				 &rpl->sregs, &rpl->msrs);

	*dest = rpl;
	*dest_size = rpl_size;

	return err;

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

static u32 kvmi_send_cr(struct kvm_vcpu *vcpu, u32 cr, u64 old_value,
			u64 new_value, u64 *ret_value)
{
	struct kvmi_event_cr e = {
		.cr = cr,
		.old_value = old_value,
		.new_value = new_value
	};
	struct kvmi_event_cr_reply r;
	int err, action;

	err = kvmi_send_event(vcpu, KVMI_EVENT_CR, &e, sizeof(e),
			      &r, sizeof(r), &action);
	if (err) {
		*ret_value = new_value;
		return KVMI_EVENT_ACTION_CONTINUE;
	}

	*ret_value = r.new_val;
	return action;
}

static bool __kvmi_cr_event(struct kvm_vcpu *vcpu, unsigned int cr,
			    unsigned long old_value, unsigned long *new_value)
{
	u64 ret_value;
	u32 action;
	bool ret = false;

	if (!test_bit(cr, IVCPU(vcpu)->cr_mask))
		return true;

	action = kvmi_send_cr(vcpu, cr, old_value, *new_value, &ret_value);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		*new_value = ret_value;
		ret = true;
		break;
	default:
		kvmi_handle_common_event_actions(vcpu, action, "CR");
	}

	return ret;
}

bool kvmi_cr_event(struct kvm_vcpu *vcpu, unsigned int cr,
		   unsigned long old_value, unsigned long *new_value)
{
	struct kvmi *ikvm;
	bool ret = true;

	if (old_value == *new_value)
		return true;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return true;

	if (is_event_enabled(vcpu, KVMI_EVENT_CR))
		ret = __kvmi_cr_event(vcpu, cr, old_value, new_value);

	kvmi_put(vcpu->kvm);

	return ret;
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

bool kvmi_arch_queue_exception(struct kvm_vcpu *vcpu)
{
	if (!vcpu->arch.exception.injected &&
	    !vcpu->arch.interrupt.injected &&
	    !vcpu->arch.nmi_injected) {
		struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
		struct x86_exception e = {
			.vector = ivcpu->exception.nr,
			.error_code_valid = ivcpu->exception.error_code_valid,
			.error_code = ivcpu->exception.error_code,
			.address = ivcpu->exception.address,
		};

		if (e.vector == PF_VECTOR)
			kvm_inject_page_fault(vcpu, &e);
		else if (e.error_code_valid)
			kvm_queue_exception_e(vcpu, e.vector, e.error_code);
		else
			kvm_queue_exception(vcpu, e.vector);

		return true;
	}

	return false;
}

static u32 kvmi_send_trap(struct kvm_vcpu *vcpu, u32 vector, u32 type,
			  u32 error_code, u64 cr2)
{
	struct kvmi_event_trap e = {
		.error_code = error_code,
		.vector = vector,
		.type = type,
		.cr2 = cr2
	};
	int err, action;

	err = kvmi_send_event(vcpu, KVMI_EVENT_TRAP, &e, sizeof(e),
			      NULL, 0, &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	return action;
}

void kvmi_arch_trap_event(struct kvm_vcpu *vcpu)
{
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

	action = kvmi_send_trap(vcpu, vector, type, err, vcpu->arch.cr2);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		break;
	default:
		kvmi_handle_common_event_actions(vcpu, action, "TRAP");
	}
}

int kvmi_arch_cmd_get_cpuid(struct kvm_vcpu *vcpu,
			    const struct kvmi_get_cpuid *req,
			    struct kvmi_get_cpuid_reply *rpl)
{
	struct kvm_cpuid_entry2 *e;

	e = kvm_find_cpuid_entry(vcpu, req->function, req->index);
	if (!e)
		return -KVM_ENOENT;

	rpl->eax = e->eax;
	rpl->ebx = e->ebx;
	rpl->ecx = e->ecx;
	rpl->edx = e->edx;

	return 0;
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

static bool is_vector_valid(u8 vector)
{
	return true;
}

static bool is_gva_valid(struct kvm_vcpu *vcpu, u64 gva)
{
	return true;
}

int kvmi_arch_cmd_inject_exception(struct kvm_vcpu *vcpu, u8 vector,
				   bool error_code_valid,
				   u32 error_code, u64 address)
{
	if (!(is_vector_valid(vector) && is_gva_valid(vcpu, address)))
		return -KVM_EINVAL;

	IVCPU(vcpu)->exception.pending = true;
	IVCPU(vcpu)->exception.nr = vector;
	IVCPU(vcpu)->exception.error_code = error_code_valid ? error_code : 0;
	IVCPU(vcpu)->exception.error_code_valid = error_code_valid;
	IVCPU(vcpu)->exception.address = address;

	return 0;
}

int kvmi_arch_cmd_control_cr(struct kvm_vcpu *vcpu,
			     const struct kvmi_control_cr *req)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	u32 cr = req->cr;

	if (req->padding1 || req->padding2)
		return -KVM_EINVAL;

	switch (cr) {
	case 0:
		break;
	case 3:
		kvm_control_cr3_write_exiting(vcpu, req->enable);
		break;
	case 4:
		break;
	default:
		return -KVM_EINVAL;
	}

	if (req->enable)
		set_bit(cr, ivcpu->cr_mask);
	else
		clear_bit(cr, ivcpu->cr_mask);

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

int kvmi_arch_cmd_get_page_write_bitmap(struct kvmi *ikvm,
					const struct kvmi_msg_hdr *msg,
					const struct kvmi_get_page_write_bitmap
					*req,
					struct kvmi_get_page_write_bitmap_reply
					**dest, size_t *dest_size)
{
	struct kvmi_get_page_write_bitmap_reply *rpl = NULL;
	size_t rpl_size = 0;
	u16 k, n = req->count;
	int ec = 0;

	if (req->padding)
		return -KVM_EINVAL;

	if (msg->size < sizeof(*req) + req->count * sizeof(req->gpa[0]))
		return -KVM_EINVAL;

	if (!kvmi_spp_enabled(ikvm))
		return -KVM_EOPNOTSUPP;

	if (req->view != 0)	/* TODO */
		return -KVM_EOPNOTSUPP;

	rpl_size = sizeof(*rpl) + sizeof(rpl->bitmap[0]) * n;
	rpl = kvmi_msg_alloc_check(rpl_size);
	if (!rpl)
		return -KVM_ENOMEM;

	for (k = 0; k < n && ec == 0; k++)
		ec = kvmi_cmd_get_page_write_bitmap(ikvm, req->gpa[k],
						    &rpl->bitmap[k]);

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

int kvmi_arch_cmd_set_page_write_bitmap(struct kvmi *ikvm,
					const struct kvmi_msg_hdr *msg,
					const struct kvmi_set_page_write_bitmap
					*req)
{
	u16 k, n = req->count;
	int ec = 0;

	if (req->padding)
		return -KVM_EINVAL;

	if (msg->size < sizeof(*req) + req->count * sizeof(req->entries[0]))
		return -KVM_EINVAL;

	if (!kvmi_spp_enabled(ikvm))
		return -KVM_EOPNOTSUPP;

	if (req->view != 0)	/* TODO */
		return -KVM_EOPNOTSUPP;

	for (k = 0; k < n && ec == 0; k++) {
		u64 gpa = req->entries[k].gpa;
		u32 bitmap = req->entries[k].bitmap;

		ec = kvmi_cmd_set_page_write_bitmap(ikvm, gpa, bitmap);
	}

	return ec;
}

int kvmi_arch_cmd_control_spp(struct kvmi *ikvm)
{
	return kvm_arch_init_spp(ikvm->kvm);
}
