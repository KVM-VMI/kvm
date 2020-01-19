/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_VMX_SPP_H
#define __KVM_X86_VMX_SPP_H

#define FULL_SPP_ACCESS		(u32)(BIT_ULL(32) - 1)

int kvm_spp_get_permission(struct kvm *kvm, u64 gfn, u32 npages,
			   u32 *access_map);
int kvm_spp_set_permission(struct kvm *kvm, u64 gfn, u32 npages,
			   u32 *access_map);
int kvm_spp_mark_protection(struct kvm *kvm, u64 gfn, u32 access);

int kvm_spp_setup_structure(struct kvm_vcpu *vcpu,
			    u32 access_map, gfn_t gfn);
u32 *gfn_to_subpage_wp_info(struct kvm_memory_slot *slot, gfn_t gfn);

#endif /* __KVM_X86_VMX_SPP_H */
