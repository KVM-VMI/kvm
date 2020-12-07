// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection (message handling) - x86
 *
 * Copyright (C) 2020 Bitdefender S.R.L.
 *
 */

#include "cpuid.h"
#include "../../../virt/kvm/introspection/kvmi_int.h"
#include "kvmi.h"

static int handle_vcpu_get_info(const struct kvmi_vcpu_msg_job *job,
				const struct kvmi_msg_hdr *msg,
				const void *req)
{
	struct kvmi_vcpu_get_info_reply rpl;

	memset(&rpl, 0, sizeof(rpl));
	if (kvm_has_tsc_control)
		rpl.tsc_speed = 1000ul * job->vcpu->arch.virtual_tsc_khz;

	return kvmi_msg_vcpu_reply(job, msg, 0, &rpl, sizeof(rpl));
}

static bool is_valid_get_regs_request(const struct kvmi_msg_hdr *msg,
				const struct kvmi_vcpu_get_registers *req)
{
	size_t req_size, msg_size;

	if (req->padding1 || req->padding2)
		return false;

	req_size = struct_size(req, msrs_idx, req->nmsrs);

	if (check_add_overflow(sizeof(struct kvmi_vcpu_hdr),
			       req_size, &msg_size))
		return false;

	if (msg_size > msg->size)
		return false;

	return true;
}

static bool is_valid_get_regs_reply(const struct kvmi_vcpu_get_registers *req,
				    size_t *ptr_rpl_size)
{
	struct kvmi_vcpu_get_registers_reply *rpl;
	size_t rpl_size, msg_size;

	rpl_size = struct_size(rpl, msrs.entries, req->nmsrs);

	if (check_add_overflow(sizeof(struct kvmi_error_code),
			       rpl_size, &msg_size))
		return false;

	if (msg_size > KVMI_MAX_MSG_SIZE)
		return false;

	*ptr_rpl_size = rpl_size;
	return true;
}

static int handle_vcpu_get_registers(const struct kvmi_vcpu_msg_job *job,
				     const struct kvmi_msg_hdr *msg,
				     const void *req)
{
	struct kvmi_vcpu_get_registers_reply *rpl = NULL;
	size_t rpl_size = 0;
	int err, ec;

	if (!is_valid_get_regs_request(msg, req) ||
	    !is_valid_get_regs_reply(req, &rpl_size)) {
		ec = -KVM_EINVAL;
		goto reply;
	}

	rpl = kvmi_msg_alloc();
	if (!rpl) {
		ec = -KVM_ENOMEM;
		goto reply;
	}

	ec = kvmi_arch_cmd_vcpu_get_registers(job->vcpu, req, rpl);

reply:
	err = kvmi_msg_vcpu_reply(job, msg, ec, rpl, rpl_size);

	kvmi_msg_free(rpl);
	return err;
}

static int handle_vcpu_set_registers(const struct kvmi_vcpu_msg_job *job,
				     const struct kvmi_msg_hdr *msg,
				     const void *req)
{
	const struct kvm_regs *regs = req;
	size_t cmd_size;
	int ec = 0;

	cmd_size = sizeof(struct kvmi_vcpu_hdr) + sizeof(*regs);

	if (cmd_size > msg->size)
		ec = -KVM_EINVAL;
	else if (!VCPUI(job->vcpu)->waiting_for_reply)
		ec = -KVM_EOPNOTSUPP;
	else
		kvmi_arch_cmd_vcpu_set_registers(job->vcpu, regs);

	return kvmi_msg_vcpu_reply(job, msg, ec, NULL, 0);
}

static int handle_vcpu_get_cpuid(const struct kvmi_vcpu_msg_job *job,
				 const struct kvmi_msg_hdr *msg,
				 const void *_req)
{
	const struct kvmi_vcpu_get_cpuid *req = _req;
	struct kvmi_vcpu_get_cpuid_reply rpl;
	struct kvm_cpuid_entry2 *entry;
	int ec = 0;

	entry = kvm_find_cpuid_entry(job->vcpu, req->function, req->index);
	if (!entry) {
		ec = -KVM_ENOENT;
	} else {
		memset(&rpl, 0, sizeof(rpl));

		rpl.eax = entry->eax;
		rpl.ebx = entry->ebx;
		rpl.ecx = entry->ecx;
		rpl.edx = entry->edx;
	}

	return kvmi_msg_vcpu_reply(job, msg, ec, &rpl, sizeof(rpl));
}

static int handle_vcpu_control_cr(const struct kvmi_vcpu_msg_job *job,
				  const struct kvmi_msg_hdr *msg,
				  const void *_req)
{
	const struct kvmi_vcpu_control_cr *req = _req;
	int ec;

	if (req->padding1 || req->padding2 || req->enable > 1)
		ec = -KVM_EINVAL;
	else if (req->cr != 0 && req->cr != 3 && req->cr != 4)
		ec = -KVM_EINVAL;
	else
		ec = kvmi_arch_cmd_vcpu_control_cr(job->vcpu, req->cr,
						   req->enable == 1);

	return kvmi_msg_vcpu_reply(job, msg, ec, NULL, 0);
}

static int handle_vcpu_inject_exception(const struct kvmi_vcpu_msg_job *job,
					const struct kvmi_msg_hdr *msg,
					const void *_req)
{
	const struct kvmi_vcpu_inject_exception *req = _req;
	struct kvm_vcpu *vcpu = job->vcpu;
	int ec;

	if (!kvmi_is_event_allowed(KVMI(vcpu->kvm), KVMI_VCPU_EVENT_TRAP))
		ec = -KVM_EPERM;
	else if (req->padding1 || req->padding2)
		ec = -KVM_EINVAL;
	else if (VCPUI(vcpu)->arch.exception.pending ||
			VCPUI(vcpu)->arch.exception.send_event)
		ec = -KVM_EBUSY;
	else
		ec = kvmi_arch_cmd_vcpu_inject_exception(vcpu, req);

	return kvmi_msg_vcpu_reply(job, msg, ec, NULL, 0);
}

static kvmi_vcpu_msg_job_fct const msg_vcpu[] = {
	[KVMI_VCPU_CONTROL_CR]       = handle_vcpu_control_cr,
	[KVMI_VCPU_GET_CPUID]        = handle_vcpu_get_cpuid,
	[KVMI_VCPU_GET_INFO]         = handle_vcpu_get_info,
	[KVMI_VCPU_GET_REGISTERS]    = handle_vcpu_get_registers,
	[KVMI_VCPU_INJECT_EXCEPTION] = handle_vcpu_inject_exception,
	[KVMI_VCPU_SET_REGISTERS]    = handle_vcpu_set_registers,
};

kvmi_vcpu_msg_job_fct kvmi_arch_vcpu_msg_handler(u16 id)
{
	return id < ARRAY_SIZE(msg_vcpu) ? msg_vcpu[id] : NULL;
}

u32 kvmi_msg_send_vcpu_cr(struct kvm_vcpu *vcpu, u32 cr, u64 old_value,
			  u64 new_value, u64 *ret_value)
{
	struct kvmi_vcpu_event_cr e;
	struct kvmi_vcpu_event_cr_reply r;
	u32 action;
	int err;

	memset(&e, 0, sizeof(e));
	e.cr = cr;
	e.old_value = old_value;
	e.new_value = new_value;

	err = kvmi_send_vcpu_event(vcpu, KVMI_VCPU_EVENT_CR, &e, sizeof(e),
				   &r, sizeof(r), &action);
	if (err) {
		action = KVMI_EVENT_ACTION_CONTINUE;
		*ret_value = new_value;
	} else {
		*ret_value = r.new_val;
	}

	return action;
}

u32 kvmi_msg_send_vcpu_trap(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	struct kvmi_vcpu_event_trap e;
	u32 action;
	int err;

	memset(&e, 0, sizeof(e));
	e.nr = vcpui->arch.exception.nr;
	e.error_code = vcpui->arch.exception.error_code;
	e.address = vcpui->arch.exception.address;

	err = __kvmi_send_vcpu_event(vcpu, KVMI_VCPU_EVENT_TRAP,
				     &e, sizeof(e), NULL, 0, &action);
	if (err)
		action = KVMI_EVENT_ACTION_CONTINUE;

	return action;
}

u32 kvmi_msg_send_vcpu_xsetbv(struct kvm_vcpu *vcpu, u8 xcr,
			      u64 old_value, u64 new_value)
{
	struct kvmi_vcpu_event_xsetbv e;
	u32 action;
	int err;

	memset(&e, 0, sizeof(e));
	e.xcr = xcr;
	e.old_value = old_value;
	e.new_value = new_value;

	err = kvmi_send_vcpu_event(vcpu, KVMI_VCPU_EVENT_XSETBV,
				   &e, sizeof(e), NULL, 0, &action);
	if (err)
		action = KVMI_EVENT_ACTION_CONTINUE;

	return action;
}
