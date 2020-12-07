/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_KVMI_HOST_H
#define _ASM_X86_KVMI_HOST_H

#include <asm/kvmi.h>

#define KVMI_NUM_CR 5

struct kvmi_monitor_interception {
	bool kvmi_intercepted;
	bool kvm_intercepted;
	bool (*monitor_fct)(struct kvm_vcpu *vcpu, bool enable);
};

struct kvmi_interception {
	bool cleanup;
	bool restore_interception;
	struct kvmi_monitor_interception breakpoint;
	struct kvmi_monitor_interception cr3w;
};

struct kvm_vcpu_arch_introspection {
	struct kvm_regs delayed_regs;
	bool have_delayed_regs;

	DECLARE_BITMAP(cr_mask, KVMI_NUM_CR);

	struct {
		u8 nr;
		u32 error_code;
		bool error_code_valid;
		u64 address;
		bool pending;
		bool send_event;
	} exception;
};

struct kvm_arch_introspection {
};

#ifdef CONFIG_KVM_INTROSPECTION

bool kvmi_monitor_bp_intercept(struct kvm_vcpu *vcpu, u32 dbg);
bool kvmi_cr_event(struct kvm_vcpu *vcpu, unsigned int cr,
		   unsigned long old_value, unsigned long *new_value);
bool kvmi_cr3_intercepted(struct kvm_vcpu *vcpu);
bool kvmi_monitor_cr3w_intercept(struct kvm_vcpu *vcpu, bool enable);
void kvmi_enter_guest(struct kvm_vcpu *vcpu);
void kvmi_xsetbv_event(struct kvm_vcpu *vcpu, u8 xcr,
		       u64 old_value, u64 new_value);
bool kvmi_descriptor_event(struct kvm_vcpu *vcpu, u8 descriptor, bool write);

#else /* CONFIG_KVM_INTROSPECTION */

static inline bool kvmi_monitor_bp_intercept(struct kvm_vcpu *vcpu, u32 dbg)
	{ return false; }
static inline bool kvmi_cr_event(struct kvm_vcpu *vcpu, unsigned int cr,
				 unsigned long old_value,
				 unsigned long *new_value)
			{ return true; }
static inline bool kvmi_cr3_intercepted(struct kvm_vcpu *vcpu) { return false; }
static inline bool kvmi_monitor_cr3w_intercept(struct kvm_vcpu *vcpu,
						bool enable) { return false; }
static inline void kvmi_enter_guest(struct kvm_vcpu *vcpu) { }
static inline void kvmi_xsetbv_event(struct kvm_vcpu *vcpu, u8 xcr,
					u64 old_value, u64 new_value) { }
static inline bool kvmi_descriptor_event(struct kvm_vcpu *vcpu, u8 descriptor,
					 bool write) { return true; }

#endif /* CONFIG_KVM_INTROSPECTION */

#endif /* _ASM_X86_KVMI_HOST_H */
