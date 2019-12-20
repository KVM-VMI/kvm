/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__LINUX_KVMI_H
#define _UAPI__LINUX_KVMI_H

/*
 * KVMI structures and definitions
 */

#include <linux/kernel.h>
#include <linux/types.h>

enum {
	KVMI_VERSION = 0x00000001
};

enum {
	KVMI_GET_VERSION      = 2,
	KVMI_VM_CHECK_COMMAND = 3,
	KVMI_VM_CHECK_EVENT   = 4,

	KVMI_NUM_MESSAGES
};

enum {
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

#endif /* _UAPI__LINUX_KVMI_H */
