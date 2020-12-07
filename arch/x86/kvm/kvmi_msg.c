// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection (message handling) - x86
 *
 * Copyright (C) 2020 Bitdefender S.R.L.
 *
 */

#include "../../../virt/kvm/introspection/kvmi_int.h"

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

static kvmi_vcpu_msg_job_fct const msg_vcpu[] = {
	[KVMI_VCPU_GET_INFO] = handle_vcpu_get_info,
};

kvmi_vcpu_msg_job_fct kvmi_arch_vcpu_msg_handler(u16 id)
{
	return id < ARRAY_SIZE(msg_vcpu) ? msg_vcpu[id] : NULL;
}
