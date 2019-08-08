/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVMI_H__
#define __KVMI_H__

#define kvmi_is_present() IS_ENABLED(CONFIG_KVM_INTROSPECTION)

#ifdef CONFIG_KVM_INTROSPECTION

int kvmi_init(void);
void kvmi_uninit(void);
void kvmi_create_vm(struct kvm *kvm);
void kvmi_destroy_vm(struct kvm *kvm);
int kvmi_ioctl_hook(struct kvm *kvm, void __user *argp);
int kvmi_ioctl_command(struct kvm *kvm, void __user *argp);
int kvmi_ioctl_event(struct kvm *kvm, void __user *argp);
int kvmi_ioctl_unhook(struct kvm *kvm, bool force_reset);

#else

static inline int kvmi_init(void) { return 0; }
static inline void kvmi_uninit(void) { }
static inline void kvmi_create_vm(struct kvm *kvm) { }
static inline void kvmi_destroy_vm(struct kvm *kvm) { }

#endif /* CONFIG_KVM_INTROSPECTION */

#endif
