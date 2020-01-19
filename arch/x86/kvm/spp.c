// SPDX-License-Identifier: GPL-2.0

#include "spp.h"

#define for_each_shadow_spp_entry(_vcpu, _addr, _walker)    \
	for (shadow_spp_walk_init(&(_walker), _vcpu, _addr);	\
	     shadow_walk_okay(&(_walker));			\
	     shadow_walk_next(&(_walker)))

static void shadow_spp_walk_init(struct kvm_shadow_walk_iterator *iterator,
				 struct kvm_vcpu *vcpu, u64 addr)
{
	iterator->addr = addr;
	iterator->shadow_addr = vcpu->kvm->arch.sppt_root;

	/* SPP Table is a 4-level paging structure */
	iterator->level = PT64_ROOT_4LEVEL;
}

struct kvm_mmu_page *kvm_spp_get_page(struct kvm_vcpu *vcpu,
				      gfn_t gfn,
				      unsigned int level)
{
	struct kvm_mmu_page *sp;
	union kvm_mmu_page_role role;

	role = vcpu->arch.mmu->mmu_role.base;
	role.level = level;
	role.direct = true;
	role.spp = true;

	for_each_valid_sp(vcpu->kvm, sp, gfn, 0) {
		if (sp->gfn != gfn)
			continue;
		if (sp->role.word != role.word)
			continue;
		if (sp->role.spp && sp->role.level == level)
			goto out;
	}

	sp = kvm_mmu_alloc_page(vcpu, true);
	sp->gfn = gfn;
	sp->role = role;
	hlist_add_head(&sp->hash_link,
		       &vcpu->kvm->arch.mmu_page_hash
		       [0][kvm_page_table_hashfn(gfn)]);
	kvm_x86_ops->clear_page(sp->spt);
out:
	return sp;
}

static void link_spp_shadow_page(struct kvm_vcpu *vcpu, u64 *sptep,
				 struct kvm_mmu_page *sp)
{
	u64 spte;

	spte = __pa(sp->spt) | PT_PRESENT_MASK;

	mmu_spte_set(sptep, spte);

	mmu_page_add_parent_pte(vcpu, sp, sptep);
}

static u64 format_spp_spte(u32 spp_wp_bitmap)
{
	u64 new_spte = 0;
	int i = 0;

	/*
	 * One 4K-page contains 32 sub-pages, they're flagged in even bits in
	 * SPPT L4E, the odd bits are reserved now, so convert 4-byte write
	 * permission bitmap to 8-byte SPP L4E format.
	 */
	for (i = 0; i < 32; i++)
		new_spte |= (spp_wp_bitmap & BIT_ULL(i)) << i;

	return new_spte;
}

static void spp_spte_set(u64 *sptep, u64 new_spte)
{
	__set_spte(sptep, new_spte);
}

int kvm_spp_setup_structure(struct kvm_vcpu *vcpu,
			    u32 access_map, gfn_t gfn)
{
	struct kvm_shadow_walk_iterator iter;
	struct kvm_mmu_page *sp;
	gfn_t pseudo_gfn;
	u64 old_spte, spp_spte;
	int ret = -EFAULT;

	if (!VALID_PAGE(vcpu->kvm->arch.sppt_root))
		return -EFAULT;

	for_each_shadow_spp_entry(vcpu, (u64)gfn << PAGE_SHIFT, iter) {
		if (iter.level == PT_PAGE_TABLE_LEVEL) {
			spp_spte = format_spp_spte(access_map);
			old_spte = mmu_spte_get_lockless(iter.sptep);
			if (old_spte != spp_spte)
				spp_spte_set(iter.sptep, spp_spte);
			ret = 0;
			break;
		}

		if (!is_shadow_present_pte(*iter.sptep)) {
			u64 base_addr = iter.addr;

			base_addr &= PT64_LVL_ADDR_MASK(iter.level);
			pseudo_gfn = base_addr >> PAGE_SHIFT;
			sp = kvm_spp_get_page(vcpu, pseudo_gfn,
					      iter.level - 1);
			link_spp_shadow_page(vcpu, iter.sptep, sp);
		} else if (iter.level == PT_DIRECTORY_LEVEL &&
			   !(spp_spte & PT_PRESENT_MASK) &&
			   (spp_spte & PT64_BASE_ADDR_MASK)) {
			spp_spte = mmu_spte_get_lockless(iter.sptep);
			spp_spte |= PT_PRESENT_MASK;
			spp_spte_set(iter.sptep, spp_spte);
		}
	}

	kvm_flush_remote_tlbs(vcpu->kvm);
	return ret;
}
