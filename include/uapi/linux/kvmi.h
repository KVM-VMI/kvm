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

#define KVMI_VM_MESSAGE_ID(id)    ((id) << 1)
#define KVMI_VCPU_MESSAGE_ID(id) (((id) << 1) | 1)

enum {
	KVMI_GET_VERSION      = KVMI_VM_MESSAGE_ID(1),
	KVMI_VM_CHECK_COMMAND = KVMI_VM_MESSAGE_ID(2),
	KVMI_VM_CHECK_EVENT   = KVMI_VM_MESSAGE_ID(3),

	KVMI_NEXT_VM_MESSAGE
};

enum {
	KVMI_NEXT_VCPU_MESSAGE
};

#define KVMI_VM_EVENT_ID(id)    ((id) << 1)
#define KVMI_VCPU_EVENT_ID(id) (((id) << 1) | 1)

enum {
	KVMI_NEXT_VM_EVENT
};

enum {
	KVMI_NEXT_VCPU_EVENT
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

#endif /* _UAPI__LINUX_KVMI_H */
