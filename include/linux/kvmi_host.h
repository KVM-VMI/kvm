/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KVMI_HOST_H
#define __KVMI_HOST_H

#include <uapi/linux/kvmi.h>

struct kvm;

#include <asm/kvmi_host.h>

struct kvm_introspection {
	struct kvm_arch_introspection arch;
	struct kvm *kvm;

	uuid_t uuid;

	struct socket *sock;
	struct task_struct *recv;
};

#ifdef CONFIG_KVM_INTROSPECTION

int kvmi_init(void);
void kvmi_uninit(void);
void kvmi_create_vm(struct kvm *kvm);
void kvmi_destroy_vm(struct kvm *kvm);

int kvmi_ioctl_hook(struct kvm *kvm, void __user *argp);
int kvmi_ioctl_unhook(struct kvm *kvm);

#else

static inline int kvmi_init(void) { return 0; }
static inline void kvmi_uninit(void) { }
static inline void kvmi_create_vm(struct kvm *kvm) { }
static inline void kvmi_destroy_vm(struct kvm *kvm) { }

#endif /* CONFIG_KVM_INTROSPECTION */

#endif
