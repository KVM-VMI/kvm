/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__LINUX_KVMI_H
#define _UAPI__LINUX_KVMI_H

/*
 * KVMI structures and definitions
 */

enum {
	KVMI_VERSION = 0x00000001
};

#define KVMI_VM_MESSAGE_ID(id)    ((id) << 1)
#define KVMI_VCPU_MESSAGE_ID(id) (((id) << 1) | 1)

enum {
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

#endif /* _UAPI__LINUX_KVMI_H */
