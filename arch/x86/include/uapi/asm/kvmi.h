/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_X86_KVMI_H
#define _UAPI_ASM_X86_KVMI_H

/*
 * KVM introspection - x86 specific structures and definitions
 */

#include <asm/kvm.h>

#define KVM_HC_XEN_HVM_OP_GUEST_REQUEST_VM_EVENT 24

struct kvmi_event_arch {
	__u8 mode;		/* 2, 4 or 8 */
	__u8 padding[7];
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	struct {
		__u64 sysenter_cs;
		__u64 sysenter_esp;
		__u64 sysenter_eip;
		__u64 efer;
		__u64 star;
		__u64 lstar;
		__u64 cstar;
		__u64 pat;
		__u64 shadow_gs;
	} msrs;
};

struct kvmi_vcpu_get_info_reply {
	__u64 tsc_speed;
};

struct kvmi_vcpu_get_registers {
	__u16 nmsrs;
	__u16 padding1;
	__u32 padding2;
	__u32 msrs_idx[0];
};

struct kvmi_vcpu_get_registers_reply {
	__u32 mode;
	__u32 padding;
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	struct kvm_msrs msrs;
};

struct kvmi_vcpu_get_cpuid {
	__u32 function;
	__u32 index;
};

struct kvmi_vcpu_get_cpuid_reply {
	__u32 eax;
	__u32 ebx;
	__u32 ecx;
	__u32 edx;
};

struct kvmi_event_breakpoint {
	__u64 gpa;
	__u8 insn_len;
	__u8 padding[7];
};

#endif /* _UAPI_ASM_X86_KVMI_H */
