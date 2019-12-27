/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVMI_INT_H__
#define __KVMI_INT_H__

#include <linux/kvm_host.h>

#define kvmi_warn(kvmi, fmt, ...) \
	kvm_info("%pU WARNING: " fmt, &kvmi->uuid, ## __VA_ARGS__)
#define kvmi_warn_once(kvmi, fmt, ...) ({                     \
		static bool __section(.data.once) __warned;   \
		if (!__warned) {                              \
			__warned = true;                      \
			kvmi_warn(kvmi, fmt, ## __VA_ARGS__); \
		}                                             \
	})
#define kvmi_err(kvmi, fmt, ...) \
	kvm_info("%pU ERROR: " fmt, &kvmi->uuid, ## __VA_ARGS__)

#define KVMI_MSG_SIZE_ALLOC (sizeof(struct kvmi_msg_hdr) + KVMI_MSG_SIZE)

#define KVMI_KNOWN_EVENTS 0

#define KVMI_KNOWN_COMMANDS ( \
			  BIT(KVMI_GET_VERSION) \
			| BIT(KVMI_VM_CHECK_COMMAND) \
			| BIT(KVMI_VM_CHECK_EVENT) \
			| BIT(KVMI_VM_GET_INFO) \
		)

#define KVMI(kvm) ((struct kvm_introspection *)((kvm)->kvmi))

/* kvmi_msg.c */
bool kvmi_sock_get(struct kvm_introspection *kvmi, int fd);
void kvmi_sock_shutdown(struct kvm_introspection *kvmi);
void kvmi_sock_put(struct kvm_introspection *kvmi);
bool kvmi_msg_process(struct kvm_introspection *kvmi);

/* kvmi.c */
void *kvmi_msg_alloc(void);
void *kvmi_msg_alloc_check(size_t size);
void kvmi_msg_free(void *addr);

#endif
