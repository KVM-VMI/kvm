/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVMI_INT_H
#define __KVMI_INT_H

#include <linux/kvm_host.h>
#include <linux/kvmi_host.h>
#include <uapi/linux/kvmi.h>

#define KVMI(kvm) ((kvm)->kvmi)
/*
 * This limit is used to accommodate the largest known fixed-length
 * message.
 */
#define KVMI_MAX_MSG_SIZE (4096 * 2 - sizeof(struct kvmi_msg_hdr))

/* kvmi_msg.c */
bool kvmi_sock_get(struct kvm_introspection *kvmi, int fd);
void kvmi_sock_shutdown(struct kvm_introspection *kvmi);
void kvmi_sock_put(struct kvm_introspection *kvmi);
bool kvmi_msg_process(struct kvm_introspection *kvmi);
int kvmi_msg_send_unhook(struct kvm_introspection *kvmi);

/* kvmi.c */
void *kvmi_msg_alloc(void);
void kvmi_msg_free(void *addr);
bool kvmi_is_command_allowed(struct kvm_introspection *kvmi, u16 id);
bool kvmi_is_event_allowed(struct kvm_introspection *kvmi, u16 id);
bool kvmi_is_known_event(u16 id);
bool kvmi_is_known_vm_event(u16 id);
int kvmi_cmd_vm_control_events(struct kvm_introspection *kvmi,
			       u16 event_id, bool enable);

/* arch */
void kvmi_arch_init_vcpu_events_mask(unsigned long *supported);

#endif
