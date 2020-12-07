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

#define KVMI_VM_MESSAGE_ID(id)    ((id) << 1)
#define KVMI_VCPU_MESSAGE_ID(id) (((id) << 1) | 1)

enum {
	KVMI_VM_EVENT = KVMI_VM_MESSAGE_ID(0),

	KVMI_GET_VERSION       = KVMI_VM_MESSAGE_ID(1),
	KVMI_VM_CHECK_COMMAND  = KVMI_VM_MESSAGE_ID(2),
	KVMI_VM_CHECK_EVENT    = KVMI_VM_MESSAGE_ID(3),
	KVMI_VM_GET_INFO       = KVMI_VM_MESSAGE_ID(4),
	KVMI_VM_CONTROL_EVENTS = KVMI_VM_MESSAGE_ID(5),
	KVMI_VM_READ_PHYSICAL  = KVMI_VM_MESSAGE_ID(6),
	KVMI_VM_WRITE_PHYSICAL = KVMI_VM_MESSAGE_ID(7),
	KVMI_VM_PAUSE_VCPU     = KVMI_VM_MESSAGE_ID(8),

	KVMI_NEXT_VM_MESSAGE
};

enum {
	KVMI_VCPU_EVENT = KVMI_VCPU_MESSAGE_ID(0),

	KVMI_VCPU_GET_INFO       = KVMI_VCPU_MESSAGE_ID(1),
	KVMI_VCPU_CONTROL_EVENTS = KVMI_VCPU_MESSAGE_ID(2),
	KVMI_VCPU_GET_REGISTERS  = KVMI_VCPU_MESSAGE_ID(3),
	KVMI_VCPU_SET_REGISTERS  = KVMI_VCPU_MESSAGE_ID(4),
	KVMI_VCPU_GET_CPUID      = KVMI_VCPU_MESSAGE_ID(5),

	KVMI_NEXT_VCPU_MESSAGE
};

#define KVMI_VM_EVENT_ID(id)    ((id) << 1)
#define KVMI_VCPU_EVENT_ID(id) (((id) << 1) | 1)

enum {
	KVMI_VM_EVENT_UNHOOK = KVMI_VM_EVENT_ID(0),

	KVMI_NEXT_VM_EVENT
};

enum {
	KVMI_VCPU_EVENT_PAUSE     = KVMI_VCPU_EVENT_ID(0),
	KVMI_VCPU_EVENT_HYPERCALL = KVMI_VCPU_EVENT_ID(1),

	KVMI_NEXT_VCPU_EVENT
};

enum {
	KVMI_EVENT_ACTION_CONTINUE = 0,
	KVMI_EVENT_ACTION_RETRY    = 1,
	KVMI_EVENT_ACTION_CRASH    = 2,
};

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
	__u32 max_msg_size;
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

struct kvmi_event_hdr {
	__u16 event;
	__u16 padding[3];
};

struct kvmi_vm_control_events {
	__u16 event_id;
	__u8 enable;
	__u8 padding1;
	__u32 padding2;
};

struct kvmi_vm_read_physical {
	__u64 gpa;
	__u16 size;
	__u16 padding1;
	__u32 padding2;
};

struct kvmi_vm_write_physical {
	__u64 gpa;
	__u16 size;
	__u16 padding1;
	__u32 padding2;
	__u8  data[0];
};

struct kvmi_vcpu_hdr {
	__u16 vcpu;
	__u16 padding1;
	__u32 padding2;
};

struct kvmi_vm_pause_vcpu {
	__u16 vcpu;
	__u8 wait;
	__u8 padding1;
	__u32 padding2;
};

struct kvmi_vcpu_event {
	__u16 size;
	__u16 vcpu;
	__u32 padding;
	struct kvmi_vcpu_event_arch arch;
};

struct kvmi_vcpu_event_reply {
	__u8 action;
	__u8 event;
	__u16 padding1;
	__u32 padding2;
};

struct kvmi_vcpu_control_events {
	__u16 event_id;
	__u8 enable;
	__u8 padding1;
	__u32 padding2;
};

#endif /* _UAPI__LINUX_KVMI_H */
