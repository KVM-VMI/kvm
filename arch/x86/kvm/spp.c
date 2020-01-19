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

/* Save reserved bit for SPP armed PTE */
void save_spp_bit(u64 *spte)
{
	*spte |= PT64_SPP_SAVED_BIT;
	*spte &= ~PT_SPP_MASK;
}

/* Restore reserved bit for SPP armed PTE */
void restore_spp_bit(u64 *spte)
{
	*spte &= ~PT64_SPP_SAVED_BIT;
	*spte |= PT_SPP_MASK;
}

bool was_spp_armed(u64 spte)
{
	return !!(spte & PT64_SPP_SAVED_BIT);
}

u32 *gfn_to_subpage_wp_info(struct kvm_memory_slot *slot, gfn_t gfn)
{
	unsigned long idx;

	if (!slot->arch.subpage_wp_info)
		return NULL;

	idx = gfn_to_index(gfn, slot->base_gfn, PT_PAGE_TABLE_LEVEL);
	if (idx > slot->npages - 1)
		return NULL;

	return &slot->arch.subpage_wp_info[idx];
}
EXPORT_SYMBOL_GPL(gfn_to_subpage_wp_info);

static bool __rmap_update_subpage_bit(struct kvm *kvm,
				      struct kvm_rmap_head *rmap_head,
				      bool setbit)
{
	struct rmap_iterator iter;
	bool flush = false;
	u64 *sptep;
	u64 spte;

	for_each_rmap_spte(rmap_head, &iter, sptep) {
		/*
		 * SPP works only when the page is write-protected
		 * and SPP bit is set in EPT leaf entry.
		 */
		flush |= spte_write_protect(sptep, false);
		spte = setbit ? (*sptep | PT_SPP_MASK) :
				(*sptep & ~PT_SPP_MASK);
		flush |= mmu_spte_update(sptep, spte);
	}

	return flush;
}

static int kvm_spp_update_write_protect(struct kvm *kvm,
					struct kvm_memory_slot *slot,
					gfn_t gfn,
					bool enable)
{
	struct kvm_rmap_head *rmap_head;
	bool flush = false;

	/*
	 * SPP is only supported with 4KB level1 memory page, check
	 * if the page is mapped in EPT leaf entry.
	 */
	rmap_head = __gfn_to_rmap(gfn, PT_PAGE_TABLE_LEVEL, slot);

	if (!rmap_head->val)
		return -EFAULT;

	flush |= __rmap_update_subpage_bit(kvm, rmap_head, enable);

	if (flush)
		kvm_flush_remote_tlbs(kvm);

	return 0;
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

static int kvm_spp_level_pages(gfn_t gfn_lower, gfn_t gfn_upper, int level)
{
	int page_num = KVM_PAGES_PER_HPAGE(level);
	gfn_t gfn_max = (gfn_lower & ~(page_num - 1)) + page_num - 1;
	int ret;

	if (gfn_upper <= gfn_max)
		ret = gfn_upper - gfn_lower + 1;
	else
		ret = gfn_max - gfn_lower + 1;

	return ret;
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
EXPORT_SYMBOL_GPL(kvm_spp_setup_structure);

int spp_flush_sppt(struct kvm *kvm, u64 gfn_base, u32 npages)
{
	struct kvm_shadow_walk_iterator iter;
	struct kvm_vcpu *vcpu;
	gfn_t gfn = gfn_base;
	gfn_t gfn_end = gfn_base + npages - 1;
	u64 spde;
	int count;
	bool flush = false;

	vcpu = kvm_get_vcpu(kvm, 0);
	if (!VALID_PAGE(vcpu->kvm->arch.sppt_root))
		return -EFAULT;

	for (; gfn <= gfn_end; gfn++) {
		for_each_shadow_spp_entry(vcpu, (u64)gfn << PAGE_SHIFT, iter) {
			if (!is_shadow_present_pte(*iter.sptep))
				break;

			if (iter.level != PT_DIRECTORY_LEVEL)
				continue;

			spde = *iter.sptep;
			spde &= ~PT_PRESENT_MASK;
			spp_spte_set(iter.sptep, spde);
			count = kvm_spp_level_pages(gfn, gfn_end,
						    PT_DIRECTORY_LEVEL);
			flush = true;
			if (count >= npages)
				goto out;
			gfn += count;
			break;
		}
	}
out:
	if (flush)
		kvm_flush_remote_tlbs(kvm);
	return 0;
}

int kvm_spp_get_permission(struct kvm *kvm, u64 gfn, u32 npages,
			   u32 *access_map)
{
	u32 *access;
	struct kvm_memory_slot *slot;
	int i;

	if (!kvm->arch.spp_active)
		return -ENODEV;

	for (i = 0; i < npages; i++, gfn++) {
		slot = gfn_to_memslot(kvm, gfn);
		if (!slot)
			return -EFAULT;
		access = gfn_to_subpage_wp_info(slot, gfn);
		if (!access)
			return -EFAULT;
		access_map[i] = *access;
	}

	return i;
}

static void kvm_spp_zap_pte(struct kvm *kvm, u64 *spte, int level)
{
	u64 pte;

	pte = *spte;
	if (is_shadow_present_pte(pte) && is_last_spte(pte, level)) {
		drop_spte(kvm, spte);
		if (is_large_pte(pte))
			--kvm->stat.lpages;
	}
}

static bool kvm_spp_flush_rmap(struct kvm *kvm, u64 gfn_min, u64 gfn_max)
{
	u64 *sptep;
	struct rmap_iterator iter;
	struct kvm_rmap_head *rmap_head;
	int level;
	struct kvm_memory_slot *slot;
	bool flush = false;

	slot = gfn_to_memslot(kvm, gfn_min);
	if (!slot)
		return false;

	for (; gfn_min <= gfn_max; gfn_min++) {
		for (level = PT_PAGE_TABLE_LEVEL;
		     level <= PT_DIRECTORY_LEVEL; level++) {
			rmap_head = __gfn_to_rmap(gfn_min, level, slot);
			for_each_rmap_spte(rmap_head, &iter, sptep) {
				pte_list_remove(rmap_head, sptep);
				flush = true;
			}
		}
	}

	return flush;
}

int kvm_spp_set_permission(struct kvm *kvm, u64 gfn, u32 npages,
			   u32 *access_map)
{
	gfn_t old_gfn = gfn;
	u32 *access;
	struct kvm_memory_slot *slot;
	struct kvm_shadow_walk_iterator iterator;
	struct kvm_vcpu *vcpu;
	gfn_t gfn_end;
	int i, count, level;
	bool flush = false;

	if (!kvm->arch.spp_active)
		return -ENODEV;

	vcpu = kvm_get_vcpu(kvm, 0);
	if (!VALID_PAGE(vcpu->kvm->arch.sppt_root))
		return -EFAULT;

	for (i = 0; i < npages; i++, gfn++) {
		slot = gfn_to_memslot(kvm, gfn);
		if (!slot)
			return -EFAULT;

		access = gfn_to_subpage_wp_info(slot, gfn);
		if (!access)
			return -EFAULT;
		*access = access_map[i];
		trace_kvm_spp_set_subpages(vcpu, gfn, *access);
	}

	gfn = old_gfn;
	gfn_end = gfn + npages - 1;
	vcpu = kvm_get_vcpu(kvm, 0);

	if (!vcpu || (vcpu && !VALID_PAGE(vcpu->arch.mmu->root_hpa)))
		goto out;

	/* Flush any existing stale mappings in EPT before set up SPP */
	flush = kvm_spp_flush_rmap(kvm, gfn, gfn_end);

	for (i = 0; gfn <= gfn_end; i++, gfn++) {
		for_each_shadow_entry(vcpu, (u64)gfn << PAGE_SHIFT, iterator) {
			if (!is_shadow_present_pte(*iterator.sptep))
				break;

			if (iterator.level == PT_PAGE_TABLE_LEVEL) {
				if (kvm_spp_mark_protection(kvm,
							    gfn,
							    access_map[i]) < 0)
					return -EFAULT;
				break;
			} else if (is_large_pte(*iterator.sptep)) {
				level = iterator.level;
				if (access_map[i] == FULL_SPP_ACCESS)
					break;
				count = kvm_spp_level_pages(gfn,
							    gfn_end,
							    level);
				/*
				 * Zap existing hugepage entry so that eligible
				 * 4KB mappings can be rebuilt in page_fault.
				 */
				kvm_spp_zap_pte(kvm, iterator.sptep, level);
				flush = true;
				if (count >= npages)
					goto out;
				gfn += count - 1;
			}
		}
	}
out:
	if (flush)
		kvm_flush_remote_tlbs(kvm);
	return npages;
}

int kvm_spp_mark_protection(struct kvm *kvm, u64 gfn, u32 access)
{
	struct kvm_memory_slot *slot;
	struct kvm_rmap_head *rmap_head;
	int ret = 0;
	bool enable;

	if (!kvm->arch.spp_active)
		return -ENODEV;

	slot = gfn_to_memslot(kvm, gfn);
	if (!slot)
		return -EFAULT;

	/*
	 * check whether the target 4KB page exists in EPT leaf
	 * entry.If it's there, just flag SPP bit of the entry,
	 * defer the setup to SPPT miss induced vm-exit  handler.
	 */
	rmap_head = __gfn_to_rmap(gfn, PT_PAGE_TABLE_LEVEL, slot);

	if (rmap_head->val) {
		enable = access != FULL_SPP_ACCESS;
		ret = kvm_spp_update_write_protect(kvm, slot, gfn, enable);
	}
	return ret;
}

int kvm_vm_ioctl_get_subpages(struct kvm *kvm,
			      u64 gfn,
			      u32 npages,
			      u32 *access_map)
{
	int ret;

	mutex_lock(&kvm->slots_lock);
	ret = kvm_spp_get_permission(kvm, gfn, npages, access_map);
	mutex_unlock(&kvm->slots_lock);

	return ret;
}

int kvm_vm_ioctl_set_subpages(struct kvm *kvm,
			      u64 gfn,
			      u32 npages,
			      u32 *access_map)
{
	int ret;

	spin_lock(&kvm->mmu_lock);
	ret = spp_flush_sppt(kvm, gfn, npages);
	spin_unlock(&kvm->mmu_lock);

	if (ret < 0)
		return ret;

	mutex_lock(&kvm->slots_lock);
	spin_lock(&kvm->mmu_lock);

	ret = kvm_spp_set_permission(kvm, gfn, npages, access_map);

	spin_unlock(&kvm->mmu_lock);
	mutex_unlock(&kvm->slots_lock);

	return ret;
}

inline u64 construct_spptp(unsigned long root_hpa)
{
	return root_hpa & PAGE_MASK;
}
EXPORT_SYMBOL_GPL(construct_spptp);
