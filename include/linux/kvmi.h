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
int kvmi_vcpu_init(struct kvm_vcpu *vcpu);
void kvmi_vcpu_uninit(struct kvm_vcpu *vcpu);
bool kvmi_breakpoint_event(struct kvm_vcpu *vcpu, u64 gva, u8 insn_len);
bool kvmi_queue_exception(struct kvm_vcpu *vcpu);
void kvmi_trap_event(struct kvm_vcpu *vcpu);
void kvmi_handle_requests(struct kvm_vcpu *vcpu);
void kvmi_init_emulate(struct kvm_vcpu *vcpu);
void kvmi_activate_rep_complete(struct kvm_vcpu *vcpu);
bool kvmi_bp_intercepted(struct kvm_vcpu *vcpu, u32 dbg);

#else

static inline int kvmi_init(void) { return 0; }
static inline void kvmi_uninit(void) { }
static inline void kvmi_create_vm(struct kvm *kvm) { }
static inline void kvmi_destroy_vm(struct kvm *kvm) { }
static inline int kvmi_vcpu_init(struct kvm_vcpu *vcpu) { return 0; }
static inline bool kvmi_breakpoint_event(struct kvm_vcpu *vcpu, u64 gva,
					 u8 insn_len)
			{ return true; }
static inline void kvmi_vcpu_uninit(struct kvm_vcpu *vcpu) { }
static inline void kvmi_handle_requests(struct kvm_vcpu *vcpu) { }
static inline bool kvmi_queue_exception(struct kvm_vcpu *vcpu) { return true; }
static inline void kvmi_trap_event(struct kvm_vcpu *vcpu) { }
static inline void kvmi_init_emulate(struct kvm_vcpu *vcpu) { }
static inline void kvmi_activate_rep_complete(struct kvm_vcpu *vcpu) { }
static inline bool kvmi_bp_intercepted(struct kvm_vcpu *vcpu, u32 dbg)
			{ return false; }

#endif /* CONFIG_KVM_INTROSPECTION */

#endif
