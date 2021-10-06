/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KVMI_HOST_H
#define __KVMI_HOST_H

#ifdef CONFIG_KVM_INTROSPECTION

#include <asm/kvmi_host.h>

struct kvm_introspection {
	struct kvm_arch_introspection arch;
	struct kvm *kvm;

	uuid_t uuid;

	struct socket *sock;
	struct task_struct *recv;

	unsigned long *cmd_allow_mask;
	unsigned long *event_allow_mask;

	unsigned long *vm_event_enable_mask;

	atomic_t ev_seq;
};

int kvmi_version(void);
int kvmi_init(void);
void kvmi_uninit(void);
void kvmi_create_vm(struct kvm *kvm);
void kvmi_destroy_vm(struct kvm *kvm);

int kvmi_ioctl_hook(struct kvm *kvm,
		    const struct kvm_introspection_hook *hook);
int kvmi_ioctl_unhook(struct kvm *kvm);
int kvmi_ioctl_command(struct kvm *kvm,
		       const struct kvm_introspection_feature *feat);
int kvmi_ioctl_event(struct kvm *kvm,
		     const struct kvm_introspection_feature *feat);
int kvmi_ioctl_preunhook(struct kvm *kvm);

#else

static inline int kvmi_version(void) { return 0; }
static inline int kvmi_init(void) { return 0; }
static inline void kvmi_uninit(void) { }
static inline void kvmi_create_vm(struct kvm *kvm) { }
static inline void kvmi_destroy_vm(struct kvm *kvm) { }

#endif /* CONFIG_KVM_INTROSPECTION */

#endif
