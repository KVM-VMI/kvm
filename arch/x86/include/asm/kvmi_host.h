/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_KVMI_HOST_H
#define _ASM_X86_KVMI_HOST_H

#include <asm/kvm_host.h>
#include <asm/kvm_page_track.h>

struct kvmi_arch_mem_access {
	unsigned long active[KVM_PAGE_TRACK_MAX][BITS_TO_LONGS(KVM_MEM_SLOTS_NUM)];
};

#ifdef CONFIG_KVM_INTROSPECTION

bool kvmi_msr_event(struct kvm_vcpu *vcpu, struct msr_data *msr);
bool kvmi_monitored_msr(struct kvm_vcpu *vcpu, u32 msr);
bool kvmi_cr_event(struct kvm_vcpu *vcpu, unsigned int cr,
		   unsigned long old_value, unsigned long *new_value);

#else /* CONFIG_KVM_INTROSPECTION */

static inline bool kvmi_msr_event(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	return true;
}

static inline bool kvmi_monitored_msr(struct kvm_vcpu *vcpu, u32 msr)
{
	return false;
}

static inline bool kvmi_cr_event(struct kvm_vcpu *vcpu, unsigned int cr,
				 unsigned long old_value,
				 unsigned long *new_value)
{
	return true;
}

#endif /* CONFIG_KVM_INTROSPECTION */

#endif /* _ASM_X86_KVMI_HOST_H */
