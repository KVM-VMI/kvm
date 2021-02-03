/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__LINUX_KVMI_H
#define _UAPI__LINUX_KVMI_H

/*
 * KVMI structures and definitions
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <asm/kvmi.h>

enum {
	KVMI_VERSION = 0x00000001
};

enum {
	KVMI_EVENT_REPLY       = 0,
	KVMI_EVENT             = 1,

	KVMI_GET_VERSION         = 2,
	KVMI_VM_CHECK_COMMAND    = 3,
	KVMI_VM_CHECK_EVENT      = 4,
	KVMI_VM_GET_INFO         = 5,
	KVMI_VM_CONTROL_EVENTS   = 8,
	KVMI_VM_READ_PHYSICAL    = 17,
	KVMI_VM_WRITE_PHYSICAL   = 18,

	KVMI_VCPU_GET_INFO         = 6,
	KVMI_VCPU_PAUSE            = 7,
	KVMI_VCPU_CONTROL_EVENTS   = 9,
	KVMI_VCPU_GET_REGISTERS    = 13,
	KVMI_VCPU_SET_REGISTERS    = 14,
	KVMI_VCPU_GET_CPUID        = 15,
	KVMI_VCPU_CONTROL_CR       = 10,
	KVMI_VCPU_INJECT_EXCEPTION = 19,

	KVMI_VM_GET_MAX_GFN = 29,

	KVMI_VCPU_GET_XSAVE     = 16,
	KVMI_VCPU_GET_MTRR_TYPE = 23,
	KVMI_VCPU_CONTROL_MSR   = 11,

	KVMI_VM_SET_PAGE_ACCESS = 21,

	KVMI_VCPU_CONTROL_SINGLESTEP = 63,
	KVMI_VCPU_TRANSLATE_GVA      = 35,
	KVMI_VCPU_GET_EPT_VIEW       = 34,
	KVMI_VCPU_SET_EPT_VIEW       = 32,
	KVMI_VCPU_CONTROL_EPT_VIEW   = 36,
	KVMI_VCPU_SET_VE_INFO        = 28,
	KVMI_VCPU_DISABLE_VE         = 33,
	KVMI_VCPU_CHANGE_GFN         = 60,

	KVMI_VM_SET_PAGE_SVE = 30,

	KVMI_VM_GET_MAP_TOKEN = 22,
	KVMI_VM_CONTROL_CMD_RESPONSE = 27,
	KVMI_VM_CONTROL_SPP = 24,
	KVMI_VM_SET_PAGE_WRITE_BITMAP = 26,

	KVMI_VCPU_GET_XCR = 37,
	KVMI_VCPU_SET_XSAVE = 38,

	KVMI_NUM_MESSAGES = 64
};

enum {
	KVMI_EVENT_UNHOOK      = 0,
	KVMI_EVENT_PAUSE_VCPU  = 10,
	KVMI_EVENT_HYPERCALL   = 5,
	KVMI_EVENT_BREAKPOINT  = 4,
	KVMI_EVENT_CR          = 1,
	KVMI_EVENT_TRAP        = 7,
	KVMI_EVENT_XSETBV      = 3,
	KVMI_EVENT_DESCRIPTOR  = 8,
	KVMI_EVENT_MSR         = 2,
	KVMI_EVENT_PF          = 6,
	KVMI_EVENT_SINGLESTEP  = 11,
	KVMI_EVENT_CREATE_VCPU = 9,
	KVMI_EVENT_CMD_ERROR   = 12,
	KVMI_EVENT_CPUID       = 13,

	KVMI_NUM_EVENTS
};

enum {
	KVMI_EVENT_ACTION_CONTINUE = 0,
	KVMI_EVENT_ACTION_RETRY    = 1,
	KVMI_EVENT_ACTION_CRASH    = 2,
};

enum {
	KVMI_PAGE_ACCESS_R = 1 << 0,
	KVMI_PAGE_ACCESS_W = 1 << 1,
	KVMI_PAGE_ACCESS_X = 1 << 2,
	KVMI_PAGE_SVE      = 1 << 3,
};

struct kvmi_msg_hdr {
	__u16 id;
	__u16 size;
	__u32 seq;
};

enum {
	KVMI_MSG_SIZE = (4096 * 2 - sizeof(struct kvmi_msg_hdr))
};

struct kvmi_error_code {
	__s32 err;
	__u32 padding;
};

struct kvmi_get_version_reply {
	__u32 version;
	__u32 padding;
	struct kvmi_features features;
};

struct kvmi_vm_check_command {
	__u16 id;
	__u16 padding1;
	__u32 padding2;
};

struct kvmi_vm_check_event {
	__u16 id;
	__u16 padding1;
	__u32 padding2;
};

struct kvmi_vm_get_info_reply {
	__u32 vcpu_count;
	__u32 padding[3];
};

struct kvmi_vm_control_events {
	__u16 event_id;
	__u8 enable;
	__u8 padding1;
	__u32 padding2;
};

struct kvmi_vm_read_physical {
	__u64 gpa;
	__u64 size;
};

struct kvmi_vm_write_physical {
	__u64 gpa;
	__u64 size;
	__u8  data[0];
};

struct kvmi_vcpu_hdr {
	__u16 vcpu;
	__u16 padding1;
	__u32 padding2;
};

struct kvmi_vcpu_pause {
	__u8 wait;
	__u8 padding1;
	__u16 padding2;
	__u32 padding3;
};

struct kvmi_vcpu_control_events {
	__u16 event_id;
	__u8 enable;
	__u8 padding1;
	__u32 padding2;
};

struct kvmi_vm_get_max_gfn_reply {
	__u64 gfn;
};

struct kvmi_page_access_entry {
	__u64 gpa;
	__u8 access;
	__u8 padding1;
	__u16 padding2;
	__u32 padding3;
};

struct kvmi_vm_set_page_access {
	__u16 view;
	__u16 count;
	__u32 padding;
	struct kvmi_page_access_entry entries[0];
};

struct kvmi_vcpu_control_singlestep {
	__u8 enable;
	__u8 padding[7];
};

struct kvmi_event {
	__u16 size;
	__u16 vcpu;
	__u8 event;
	__u8 padding[3];
	struct kvmi_event_arch arch;
};

struct kvmi_event_reply {
	__u8 action;
	__u8 event;
	__u16 padding1;
	__u32 padding2;
};

struct kvmi_event_pf {
	__u64 gva;
	__u64 gpa;
	__u8 access;
	__u8 padding1;
	__u16 padding2;
	__u32 padding3;
};

struct kvmi_event_pf_reply {
	__u64 ctx_addr;
	__u32 ctx_size;
	__u8 padding1;
	__u8 rep_complete;
	__u16 padding2;
	__u8 ctx_data[256];
};

struct kvmi_event_singlestep {
	__u8 failed;
	__u8 padding[7];
};

struct kvmi_vcpu_translate_gva {
	__u64 gva;
};

struct kvmi_vcpu_translate_gva_reply {
	__u64 gpa;
};

struct kvmi_map_mem_token {
	__u64 token[4];
};

struct kvmi_vm_get_map_token_reply {
	struct kvmi_map_mem_token token;
};

struct kvmi_vm_control_cmd_response {
	__u8 enable;
	__u8 now;
	__u8 flags;
	__u8 padding1;
	__u32 padding2;
};

struct kvmi_event_cmd_error {
	__s32 err;
	__u32 msg_seq;
	__u16 msg_id;
	__u16 padding[3];
};

struct kvmi_guest_mem_map {
	struct kvmi_map_mem_token token;	/* In */
	__u64 gpa;				/* In/Out */
	__u64 length;				/* Out */
};

#define KVM_GUEST_MEM_START	_IOW('i', 0x01, void *)
#define KVM_GUEST_MEM_MAP	_IOWR('i', 0x02, struct kvmi_guest_mem_map)
#define KVM_GUEST_MEM_UNMAP	_IOW('i', 0x03, unsigned long)

/* KVM_HC_INTROSPECTION codes */
#define KVMI_HC_START		0x01
#define KVMI_HC_MAP		0x02
#define KVMI_HC_UNMAP		0x03
#define KVMI_HC_END		0x04

#endif /* _UAPI__LINUX_KVMI_H */
