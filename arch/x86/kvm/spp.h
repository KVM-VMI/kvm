/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_VMX_SPP_H
#define __KVM_X86_VMX_SPP_H

#define FULL_SPP_ACCESS		(u32)(BIT_ULL(32) - 1)
#define KVM_SUBPAGE_MAX_PAGES   512
#define MAX_ENTRIES_PER_MMUPAGE BIT(9)
#define SPP_STATUS_VMX_SUPPORT   0x1
#define SPP_STATUS_EPT_SUPPORT   0x2

int spp_init(struct kvm *kvm);
void kvm_spp_free_memslot(struct kvm_memory_slot *free,
			  struct kvm_memory_slot *dont);
int kvm_spp_get_permission(struct kvm *kvm, u64 gfn, u32 npages,
			   u32 *access_map);
int kvm_spp_set_permission(struct kvm *kvm, u64 gfn, u32 npages,
			   u32 *access_map);
int kvm_spp_mark_protection(struct kvm *kvm, u64 gfn, u32 access);
bool check_spp_protection(struct kvm_vcpu *vcpu, gfn_t gfn,
			  bool *force_pt_level, int *level);
int kvm_vm_ioctl_get_subpages(struct kvm *kvm,
			      u64 gfn,
			      u32 npages,
			      u32 *access_map);
int kvm_vm_ioctl_set_subpages(struct kvm *kvm,
			      u64 gfn,
			      u32 npages,
			      u32 *access_map);
int kvm_spp_setup_structure(struct kvm_vcpu *vcpu,
			    u32 access_map, gfn_t gfn);
u32 *gfn_to_subpage_wp_info(struct kvm_memory_slot *slot, gfn_t gfn);
int spp_flush_sppt(struct kvm *kvm, u64 gfn_base, u32 npages);
void save_spp_bit(u64 *spte);
void restore_spp_bit(u64 *spte);
bool was_spp_armed(u64 spte);
u64 construct_spptp(unsigned long root_hpa);

#endif /* __KVM_X86_VMX_SPP_H */
