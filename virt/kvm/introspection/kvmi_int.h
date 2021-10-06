/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVMI_INT_H
#define __KVMI_INT_H

#include <linux/kvm_host.h>
#include <linux/kvmi_host.h>
#include <uapi/linux/kvmi.h>

#define KVMI(kvm) ((kvm)->kvmi)

/* kvmi_msg.c */
bool kvmi_sock_get(struct kvm_introspection *kvmi, int fd);
void kvmi_sock_shutdown(struct kvm_introspection *kvmi);
void kvmi_sock_put(struct kvm_introspection *kvmi);
bool kvmi_msg_process(struct kvm_introspection *kvmi);

#endif
