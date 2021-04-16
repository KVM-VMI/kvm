/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_KVMI_HOST_H
#define _ASM_X86_KVMI_HOST_H

#include <asm/kvm_page_track.h>

struct msr_data;

#define KVMI_NUM_CR 5
#define KVMI_NUM_MSR 0x2000
#define KVMI_MAX_ACCESS_TREES KVM_MAX_EPT_VIEWS

struct kvmi_monitor_interception {
	bool kvmi_intercepted;
	bool kvm_intercepted;
	bool (*monitor_fct)(struct kvm_vcpu *vcpu, bool enable);
};

struct kvmi_interception {
	bool restore_interception;
	struct kvmi_monitor_interception breakpoint;
	struct kvmi_monitor_interception cr3w;
	struct kvmi_monitor_interception descriptor;
	struct {
		struct {
			DECLARE_BITMAP(low, KVMI_NUM_MSR);
			DECLARE_BITMAP(high, KVMI_NUM_MSR);
		} kvmi_mask;
		struct {
			DECLARE_BITMAP(low, KVMI_NUM_MSR);
			DECLARE_BITMAP(high, KVMI_NUM_MSR);
		} kvm_mask;
		bool (*monitor_fct)(struct kvm_vcpu *vcpu, u32 msr,
				    bool enable);
	} msrw;
};

struct kvm_vcpu_arch_introspection {
	DECLARE_BITMAP(cr_mask, KVMI_NUM_CR);
};

struct kvm_arch_introspection {
	struct kvm_page_track_notifier_node kptn_node;

	struct {
		bool initialized;
		bool enabled;
	} spp;
};

#ifdef CONFIG_KVM_INTROSPECTION

bool kvmi_monitor_bp_intercept(struct kvm_vcpu *vcpu, u32 dbg);
bool kvmi_cr_event(struct kvm_vcpu *vcpu, unsigned int cr,
		   unsigned long old_value, unsigned long *new_value);
bool kvmi_cr3_intercepted(struct kvm_vcpu *vcpu);
bool kvmi_monitor_cr3w_intercept(struct kvm_vcpu *vcpu, bool enable);
void kvmi_xsetbv_event(struct kvm_vcpu *vcpu);
bool kvmi_monitor_desc_intercept(struct kvm_vcpu *vcpu, bool enable);
bool kvmi_descriptor_event(struct kvm_vcpu *vcpu, u8 descriptor, u8 write);
bool kvmi_msr_event(struct kvm_vcpu *vcpu, struct msr_data *msr);
bool kvmi_monitor_msrw_intercept(struct kvm_vcpu *vcpu, u32 msr, bool enable);
bool kvmi_msrw_intercept_originator(struct kvm_vcpu *vcpu);
bool kvmi_update_ad_flags(struct kvm_vcpu *vcpu);
bool kvmi_cpuid_event(struct kvm_vcpu *vcpu, u8 insn_len,
		      unsigned int function, unsigned int index);

#else /* CONFIG_KVM_INTROSPECTION */

static inline bool kvmi_monitor_bp_intercept(struct kvm_vcpu *vcpu, u32 dbg)
	{ return false; }
static inline bool kvmi_cr_event(struct kvm_vcpu *vcpu, unsigned int cr,
				 unsigned long old_value,
				 unsigned long *new_value) { return true; }
static inline bool kvmi_cr3_intercepted(struct kvm_vcpu *vcpu) { return false; }
static inline bool kvmi_monitor_cr3w_intercept(struct kvm_vcpu *vcpu,
						bool enable) { return false; }
static inline void kvmi_xsetbv_event(struct kvm_vcpu *vcpu) { }
static inline bool kvmi_monitor_desc_intercept(struct kvm_vcpu *vcpu,
					       bool enable) { return false; }
static inline bool kvmi_descriptor_event(struct kvm_vcpu *vcpu, u8 descriptor,
					 u8 write) { return true; }
static inline bool kvmi_msr_event(struct kvm_vcpu *vcpu, struct msr_data *msr)
				{ return true; }
static inline bool kvmi_monitor_msrw_intercept(struct kvm_vcpu *vcpu, u32 msr,
					       bool enable) { return false; }
static inline bool kvmi_msrw_intercept_originator(struct kvm_vcpu *vcpu)
				{ return false; }
bool kvmi_update_ad_flags(struct kvm_vcpu *vcpu) { return false; }
static inline bool kvmi_cpuid_event(struct kvm_vcpu *vcpu, u8 insn_len,
				    unsigned int function, unsigned int index);

#endif /* CONFIG_KVM_INTROSPECTION */

#endif /* _ASM_X86_KVMI_HOST_H */
