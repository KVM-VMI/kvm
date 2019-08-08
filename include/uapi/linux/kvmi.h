/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__LINUX_KVMI_H
#define _UAPI__LINUX_KVMI_H

/*
 * KVMI structures and definitions
 */

#include <linux/kernel.h>
#include <linux/types.h>

#define KVMI_VERSION 0x00000001

enum {
	KVMI_EVENT_REPLY           = 0,
	KVMI_EVENT                 = 1,

	KVMI_FIRST_COMMAND         = 2,

	KVMI_GET_VERSION           = 2,
	KVMI_CHECK_COMMAND         = 3,
	KVMI_CHECK_EVENT           = 4,
	KVMI_GET_GUEST_INFO        = 5,
	KVMI_GET_VCPU_INFO         = 6,
	KVMI_PAUSE_VCPU            = 7,
	KVMI_CONTROL_VM_EVENTS     = 8,
	KVMI_CONTROL_EVENTS        = 9,
	KVMI_CONTROL_CR            = 10,
	KVMI_CONTROL_MSR           = 11,
	KVMI_CONTROL_VE            = 12,
	KVMI_GET_REGISTERS         = 13,
	KVMI_SET_REGISTERS         = 14,
	KVMI_GET_CPUID             = 15,
	KVMI_GET_XSAVE             = 16,
	KVMI_READ_PHYSICAL         = 17,
	KVMI_WRITE_PHYSICAL        = 18,
	KVMI_INJECT_EXCEPTION      = 19,
	KVMI_GET_PAGE_ACCESS       = 20,
	KVMI_SET_PAGE_ACCESS       = 21,
	KVMI_GET_MAP_TOKEN         = 22,
	KVMI_GET_MTRR_TYPE         = 23,
	KVMI_CONTROL_SPP           = 24,
	KVMI_GET_PAGE_WRITE_BITMAP = 25,
	KVMI_SET_PAGE_WRITE_BITMAP = 26,
	KVMI_CONTROL_CMD_RESPONSE  = 27,

	KVMI_NEXT_AVAILABLE_COMMAND,

};

enum {
	KVMI_EVENT_UNHOOK      = 0,
	KVMI_EVENT_CR	       = 1,
	KVMI_EVENT_MSR	       = 2,
	KVMI_EVENT_XSETBV      = 3,
	KVMI_EVENT_BREAKPOINT  = 4,
	KVMI_EVENT_HYPERCALL   = 5,
	KVMI_EVENT_PF	       = 6,
	KVMI_EVENT_TRAP	       = 7,
	KVMI_EVENT_DESCRIPTOR  = 8,
	KVMI_EVENT_CREATE_VCPU = 9,
	KVMI_EVENT_PAUSE_VCPU  = 10,
	KVMI_EVENT_SINGLESTEP  = 11,

	KVMI_NUM_EVENTS
};

#define KVMI_MSG_SIZE (4096 - sizeof(struct kvmi_msg_hdr))

struct kvmi_msg_hdr {
	__u16 id;
	__u16 size;
	__u32 seq;
};

struct kvmi_error_code {
	__s32 err;
	__u32 padding;
};

struct kvmi_get_version_reply {
	__u32 version;
	__u32 padding;
};

struct kvmi_control_cmd_response {
	__u8 enable;
	__u8 now;
	__u16 padding1;
	__u32 padding2;
};

struct kvmi_check_command {
	__u16 id;
	__u16 padding1;
	__u32 padding2;
};

struct kvmi_check_event {
	__u16 id;
	__u16 padding1;
	__u32 padding2;
};

struct kvmi_get_guest_info_reply {
	__u32 vcpu_count;
	__u32 padding[3];
};

struct kvmi_control_vm_events {
	__u16 event_id;
	__u8 enable;
	__u8 padding1;
	__u32 padding2;
};

#endif /* _UAPI__LINUX_KVMI_H */
