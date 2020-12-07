// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection (message handling) - x86
 *
 * Copyright (C) 2020 Bitdefender S.R.L.
 *
 */

#include "../../../virt/kvm/introspection/kvmi_int.h"

static kvmi_vcpu_msg_job_fct const msg_vcpu[] = {
};

kvmi_vcpu_msg_job_fct kvmi_arch_vcpu_msg_handler(u16 id)
{
	return id < ARRAY_SIZE(msg_vcpu) ? msg_vcpu[id] : NULL;
}
