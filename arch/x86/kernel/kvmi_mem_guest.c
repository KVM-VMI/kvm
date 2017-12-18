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

long kvmi_arch_map_hc(struct kvmi_map_mem_token *tknp,
		       gpa_t req_gpa, gpa_t map_gpa)
{
	return kvm_hypercall3(KVM_HC_MEM_MAP, (unsigned long)tknp,
			      req_gpa, map_gpa);
}

long kvmi_arch_unmap_hc(gpa_t map_gpa)
{
	return kvm_hypercall1(KVM_HC_MEM_UNMAP, map_gpa);
}
