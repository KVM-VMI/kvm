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
	__u8 padding1;
	__u16 view;
	__u32 padding2;
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

struct kvmi_vcpu_control_cr {
	__u8 enable;
	__u8 padding1;
	__u16 padding2;
	__u32 cr;
};

struct kvmi_event_cr {
	__u16 cr;
	__u16 padding[3];
	__u64 old_value;
	__u64 new_value;
};

struct kvmi_event_cr_reply {
	__u64 new_val;
};

struct kvmi_event_trap {
	__u8 vector;
	__u8 padding1;
	__u16 padding2;
	__u32 error_code;
	__u64 cr2;
};

struct kvmi_vcpu_inject_exception {
	__u8 nr;
	__u8 padding1;
	__u16 padding2;
	__u32 error_code;
	__u64 address;
};

struct kvmi_vcpu_get_xsave_reply {
	__u32 region[0];
};

struct kvmi_vcpu_set_xsave {
	__u32 region[0];
};

struct kvmi_vcpu_get_mtrr_type {
	__u64 gpa;
};

struct kvmi_vcpu_get_mtrr_type_reply {
	__u8 type;
	__u8 padding[7];
};

#define KVMI_DESC_IDTR  1
#define KVMI_DESC_GDTR  2
#define KVMI_DESC_LDTR  3
#define KVMI_DESC_TR    4

struct kvmi_event_descriptor {
	__u8 descriptor;
	__u8 write;
	__u8 padding[6];
};

struct kvmi_vcpu_control_msr {
	__u8 enable;
	__u8 padding1;
	__u16 padding2;
	__u32 msr;
};

struct kvmi_event_msr {
	__u32 msr;
	__u32 padding;
	__u64 old_value;
	__u64 new_value;
};

struct kvmi_event_cpuid {
	__u32 function;
	__u32 index;
	__u8  insn_length;
	__u8  padding1[3];
	__u32 padding2;
};

struct kvmi_event_msr_reply {
	__u64 new_val;
};

struct kvmi_features {
	__u8 spp;
	__u8 vmfunc;
	__u8 eptp;
	__u8 ve;
	__u8 singlestep;
	__u8 padding[3];
};

struct kvmi_vcpu_get_ept_view_reply {
	__u16 view;
	__u16 padding1;
	__u32 padding2;
};

struct kvmi_vcpu_set_ept_view {
	__u16 view;
	__u16 padding1;
	__u32 padding2;
};

struct kvmi_vcpu_control_ept_view {
	__u16 view;
	__u8  visible;
	__u8  padding1;
	__u32 padding2;
};

struct kvmi_vcpu_set_ve_info {
	__u64 gpa;
	__u8 trigger_vmexit;
	__u8 padding1;
	__u16 padding2;
	__u32 padding3;
};

struct kvmi_vcpu_change_gfn {
	__u64 old_gfn;
	__u64 new_gfn;
};

struct kvmi_vm_set_page_sve {
	__u16 view;
	__u8 suppress;
	__u8 padding1;
	__u32 padding2;
	__u64 gpa;
};

struct kvmi_vm_control_spp {
	__u8 enable;
	__u8 padding1;
	__u16 padding2;
	__u32 padding3;
};

struct kvmi_page_write_bitmap_entry {
	__u64 gpa;
	__u32 bitmap;
	__u32 padding;
};

struct kvmi_vm_set_page_write_bitmap {
	__u16 padding1;
	__u16 count;
	__u32 padding2;
	struct kvmi_page_write_bitmap_entry entries[0];
};

struct kvmi_vcpu_get_xcr {
	__u8 xcr;
	__u8 padding[7];
};

struct kvmi_vcpu_get_xcr_reply {
	u64 value;
};

#endif /* _UAPI_ASM_X86_KVMI_H */
