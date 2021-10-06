/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_X86_KVMI_H
#define _UAPI_ASM_X86_KVMI_H

/*
 * KVM introspection - x86 specific structures and definitions
 */

struct kvmi_vcpu_get_info_reply {
	__u64 tsc_speed;
};

#endif /* _UAPI_ASM_X86_KVMI_H */
