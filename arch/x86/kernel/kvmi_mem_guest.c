// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection guest implementation
 *
 * Copyright (C) 2017 Bitdefender S.R.L.
 *
 * Author:
 *   Mircea Cirjaliu <mcirjaliu@bitdefender.com>
 */

#include <uapi/linux/kvmi.h>
#include <uapi/linux/kvm_para.h>
#include <linux/kvm_types.h>
#include <asm/kvm_para.h>

long kvmi_arch_guest_start(void *request)
{
        return kvm_hypercall2(KVM_HC_INTROSPECTION, KVMI_HC_START,
                              (unsigned long)request);
}

long kvmi_arch_guest_map(struct kvmi_map_mem_token *token, void *request)
{
	return kvm_hypercall3(KVM_HC_INTROSPECTION, KVMI_HC_MAP,
			      (unsigned long)token, (unsigned long)request);
}

long kvmi_arch_guest_unmap(void *request)
{
	return kvm_hypercall2(KVM_HC_INTROSPECTION, KVMI_HC_UNMAP,
		              (unsigned long)request);
}

long kvmi_arch_guest_end(void *request)
{
        return kvm_hypercall2(KVM_HC_INTROSPECTION, KVMI_HC_END,
                              (unsigned long)request);
}
