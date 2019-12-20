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
	KVMI_EVENT             = 1,

	KVMI_GET_VERSION       = 2,
	KVMI_VM_CHECK_COMMAND  = 3,
	KVMI_VM_CHECK_EVENT    = 4,
	KVMI_VM_GET_INFO       = 5,
	KVMI_VM_CONTROL_EVENTS = 6,

	KVMI_NUM_MESSAGES
};

enum {
	KVMI_EVENT_UNHOOK = 0,

	KVMI_NUM_EVENTS
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

struct kvmi_event {
	__u16 size;
	__u16 vcpu;
	__u8 event;
	__u8 padding[3];
	struct kvmi_event_arch arch;
};

#endif /* _UAPI__LINUX_KVMI_H */
