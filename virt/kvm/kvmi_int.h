/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVMI_INT_H__
#define __KVMI_INT_H__

#include <linux/types.h>
#include <linux/kvm_host.h>

#include <uapi/linux/kvmi.h>

#define kvmi_debug(ikvm, fmt, ...) \
	kvm_debug("%pU " fmt, &ikvm->uuid, ## __VA_ARGS__)
#define kvmi_info(ikvm, fmt, ...) \
	kvm_info("%pU " fmt, &ikvm->uuid, ## __VA_ARGS__)
#define kvmi_warn(ikvm, fmt, ...) \
	kvm_info("%pU WARNING: " fmt, &ikvm->uuid, ## __VA_ARGS__)
#define kvmi_warn_once(ikvm, fmt, ...) ({                     \
		static bool __section(.data.once) __warned;   \
		if (!__warned) {                              \
			__warned = true;                      \
			kvmi_warn(ikvm, fmt, ## __VA_ARGS__); \
		}                                             \
	})
#define kvmi_err(ikvm, fmt, ...) \
	kvm_info("%pU ERROR: " fmt, &ikvm->uuid, ## __VA_ARGS__)

#define IKVM(kvm) ((struct kvmi *)((kvm)->kvmi))

struct kvmi {
	struct kvm *kvm;

	struct socket *sock;
	struct task_struct *recv;

	uuid_t uuid;
};

/* kvmi_msg.c */
bool kvmi_sock_get(struct kvmi *ikvm, int fd);
void kvmi_sock_shutdown(struct kvmi *ikvm);
void kvmi_sock_put(struct kvmi *ikvm);
bool kvmi_msg_process(struct kvmi *ikvm);

#endif
