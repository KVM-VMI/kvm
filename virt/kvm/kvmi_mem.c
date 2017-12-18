// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection memory mapping implementation
 *
 * Copyright (C) 2017 Bitdefender S.R.L.
 *
 * Author:
 *   Mircea Cirjaliu <mcirjaliu@bitdefender.com>
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/rmap.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/printk.h>
#include <linux/kvmi.h>
#include <linux/huge_mm.h>

#include <uapi/linux/kvmi.h>

#include "kvmi_int.h"


static struct list_head mapping_list;
static spinlock_t mapping_lock;

struct host_map {
	struct list_head mapping_list;
	gpa_t map_gpa;
	struct kvm *machine;
	gpa_t req_gpa;
};


static struct list_head token_list;
static spinlock_t token_lock;

struct token_entry {
	struct list_head token_list;
	struct kvmi_map_mem_token token;
	struct kvm *kvm;
};


int kvmi_store_token(struct kvm *kvm, struct kvmi_map_mem_token *token)
{
	struct token_entry *tep;

	print_hex_dump_debug("kvmi: new token ", DUMP_PREFIX_NONE,
			     32, 1, token, sizeof(*token),
			     false);

	/* TODO: Should we limit the number of these tokens?
	 * Have only one for every VM?
	 */
	tep = kmalloc(sizeof(*tep), GFP_KERNEL);
	if (tep == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&tep->token_list);
	memcpy(&tep->token, token, sizeof(*token));
	tep->kvm = kvm;

	spin_lock(&token_lock);
	list_add_tail(&tep->token_list, &token_list);
	spin_unlock(&token_lock);

	return 0;
}

static struct kvm *find_machine_at(struct kvm_vcpu *vcpu, gva_t tkn_gva)
{
	long result;
	gpa_t tkn_gpa;
	struct kvmi_map_mem_token token;
	struct list_head *cur;
	struct token_entry *tep, *found = NULL;
	struct kvm *target_kvm = NULL;

	/* machine token is passed as pointer */
	tkn_gpa = kvm_mmu_gva_to_gpa_system(vcpu, tkn_gva, NULL);
	if (tkn_gpa == UNMAPPED_GVA)
		return NULL;

	/* copy token to local address space */
	result = kvm_read_guest(vcpu->kvm, tkn_gpa, &token, sizeof(token));
	if (IS_ERR_VALUE(result)) {
		kvm_err("kvmi: failed copying token from user\n");
		return ERR_PTR(result);
	}

	/* consume token & find the VM */
	spin_lock(&token_lock);
	list_for_each(cur, &token_list) {
		tep = list_entry(cur, struct token_entry, token_list);

		if (!memcmp(&token, &tep->token, sizeof(token))) {
			list_del(&tep->token_list);
			found = tep;
			break;
		}
	}
	spin_unlock(&token_lock);

	if (found != NULL) {
		target_kvm = found->kvm;
		kfree(found);
	}

	return target_kvm;
}

static void remove_vm_token(struct kvm *kvm)
{
	struct list_head *cur, *next;
	struct token_entry *tep;

	spin_lock(&token_lock);
	list_for_each_safe(cur, next, &token_list) {
		tep = list_entry(cur, struct token_entry, token_list);

		if (tep->kvm == kvm) {
			list_del(&tep->token_list);
			kfree(tep);
		}
	}
	spin_unlock(&token_lock);
}


static int add_to_list(gpa_t map_gpa, struct kvm *machine, gpa_t req_gpa)
{
	struct host_map *map;

	map = kmalloc(sizeof(*map), GFP_KERNEL);
	if (map == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&map->mapping_list);
	map->map_gpa = map_gpa;
	map->machine = machine;
	map->req_gpa = req_gpa;

	spin_lock(&mapping_lock);
	list_add_tail(&map->mapping_list, &mapping_list);
	spin_unlock(&mapping_lock);

	return 0;
}

static struct host_map *extract_from_list(gpa_t map_gpa)
{
	struct list_head *cur;
	struct host_map *map;

	spin_lock(&mapping_lock);
	list_for_each(cur, &mapping_list) {
		map = list_entry(cur, struct host_map, mapping_list);

		/* found - extract and return */
		if (map->map_gpa == map_gpa) {
			list_del(&map->mapping_list);
			spin_unlock(&mapping_lock);

			return map;
		}
	}
	spin_unlock(&mapping_lock);

	return NULL;
}

static void remove_vm_from_list(struct kvm *kvm)
{
	struct list_head *cur, *next;
	struct host_map *map;

	spin_lock(&mapping_lock);

	list_for_each_safe(cur, next, &mapping_list) {
		map = list_entry(cur, struct host_map, mapping_list);

		if (map->machine == kvm) {
			list_del(&map->mapping_list);
			kfree(map);
		}
	}

	spin_unlock(&mapping_lock);
}

static void remove_entry(struct host_map *map)
{
	kfree(map);
}


static struct vm_area_struct *isolate_page_vma(struct vm_area_struct *vma,
					       unsigned long addr)
{
	int result;

	/* corner case */
	if (vma_pages(vma) == 1)
		return vma;

	if (addr != vma->vm_start) {
		/* first split only if address in the middle */
		result = split_vma(vma->vm_mm, vma, addr, false);
		if (IS_ERR_VALUE((long)result))
			return ERR_PTR((long)result);

		vma = find_vma(vma->vm_mm, addr);
		if (vma == NULL)
			return ERR_PTR(-ENOENT);

		/* corner case (again) */
		if (vma_pages(vma) == 1)
			return vma;
	}

	result = split_vma(vma->vm_mm, vma, addr + PAGE_SIZE, true);
	if (IS_ERR_VALUE((long)result))
		return ERR_PTR((long)result);

	vma = find_vma(vma->vm_mm, addr);
	if (vma == NULL)
		return ERR_PTR(-ENOENT);

	BUG_ON(vma_pages(vma) != 1);

	return vma;
}

static int redirect_rmap(struct vm_area_struct *req_vma, struct page *req_page,
			 struct vm_area_struct *map_vma)
{
	int result;

	unlink_anon_vmas(map_vma);

	result = anon_vma_fork(map_vma, req_vma);
	if (!IS_ERR_VALUE((long)result))
		page_dup_rmap(req_page, false);

	return result;
}

static int host_map_fix_ptes(struct vm_area_struct *map_vma, hva_t map_hva,
			     struct page *req_page, struct page *map_page)
{
	struct mm_struct *map_mm = map_vma->vm_mm;

	pmd_t *pmd;
	pte_t *ptep;
	spinlock_t *ptl;
	pte_t newpte;

	unsigned long mmun_start;
	unsigned long mmun_end;

	/* classic replace_page() code */
	pmd = mm_find_pmd(map_mm, map_hva);
	if (!pmd)
		return -EFAULT;

	mmun_start = map_hva;
	mmun_end = map_hva + PAGE_SIZE;
	mmu_notifier_invalidate_range_start(map_mm, mmun_start, mmun_end);

	ptep = pte_offset_map_lock(map_mm, pmd, map_hva, &ptl);

	/* create new PTE based on requested page */
	newpte = mk_pte(req_page, map_vma->vm_page_prot);
	newpte = pte_set_flags(newpte, pte_flags(*ptep));

	flush_cache_page(map_vma, map_hva, pte_pfn(*ptep));
	ptep_clear_flush_notify(map_vma, map_hva, ptep);
	set_pte_at_notify(map_mm, map_hva, ptep, newpte);

	pte_unmap_unlock(ptep, ptl);

	mmu_notifier_invalidate_range_end(map_mm, mmun_start, mmun_end);

	return 0;
}

static void discard_page(struct page *map_page)
{
	lock_page(map_page);
	// TODO: put_anon_vma() ???? - should be here
	page_remove_rmap(map_page, false);
	if (!page_mapped(map_page))
		try_to_free_swap(map_page);
	unlock_page(map_page);
	put_page(map_page);
}

static void kvmi_split_huge_pmd(struct vm_area_struct *req_vma,
				hva_t req_hva, struct page *req_page)
{
	bool tail = false;

	/* move reference count from compound head... */
	if (PageTail(req_page)) {
		tail = true;
		put_page(req_page);
	}

	if (PageCompound(req_page))
		split_huge_pmd_address(req_vma, req_hva, false, NULL);

	/* ... to the actual page, after splitting */
	if (tail)
		get_page(req_page);
}

static int kvmi_map_action(struct mm_struct *req_mm, hva_t req_hva,
			   struct mm_struct *map_mm, hva_t map_hva)
{
	struct vm_area_struct *req_vma;
	struct page *req_page = NULL;

	struct vm_area_struct *map_vma;
	struct page *map_page;

	long nrpages;
	int result = 0;

	/* VMAs will be modified */
	down_write(&req_mm->mmap_sem);
	down_write(&map_mm->mmap_sem);

	/* get host page corresponding to requested address */
	nrpages = get_user_pages_remote(NULL, req_mm,
		req_hva, 1, 0,
		&req_page, &req_vma, NULL);
	if (nrpages == 0) {
		kvm_err("kvmi: no page for req_hva %016lx\n", req_hva);
		result = -ENOENT;
		goto out_err;
	} else if (IS_ERR_VALUE(nrpages)) {
		result = nrpages;
		kvm_err("kvmi: get_user_pages_remote() failed with result %d\n",
			result);
		goto out_err;
	}

	if (IS_ENABLED(CONFIG_DEBUG_VM))
		dump_page(req_page, "req_page before remap");

	/* find (not get) local page corresponding to target address */
	map_vma = find_vma(map_mm, map_hva);
	if (map_vma == NULL) {
		kvm_err("kvmi: no local VMA found for remapping\n");
		result = -ENOENT;
		goto out_err;
	}

	map_page = follow_page(map_vma, map_hva, 0);
	if (IS_ERR_VALUE(map_page)) {
		result = PTR_ERR(map_page);
		kvm_debug("kvmi: follow_page() failed with result %d\n",
			result);
		goto out_err;
	} else if (map_page == NULL) {
		result = -ENOENT;
		kvm_debug("kvmi: follow_page() returned no page\n");
		goto out_err;
	}

	if (IS_ENABLED(CONFIG_DEBUG_VM))
		dump_page(map_page, "map_page before remap");

	/* split local VMA for rmap redirecting */
	map_vma = isolate_page_vma(map_vma, map_hva);
	if (IS_ERR_VALUE(map_vma)) {
		result = PTR_ERR(map_vma);
		kvm_debug("kvmi: isolate_page_vma() failed with result %d\n",
			result);
		goto out_err;
	}

	/* split remote huge page */
	kvmi_split_huge_pmd(req_vma, req_hva, req_page);

	/* re-link VMAs */
	result = redirect_rmap(req_vma, req_page, map_vma);
	if (IS_ERR_VALUE((long)result))
		goto out_err;

	/* also redirect page tables */
	result = host_map_fix_ptes(map_vma, map_hva, req_page, map_page);
	if (IS_ERR_VALUE((long)result))
		goto out_err;

	/* the old page will be discarded */
	discard_page(map_page);
	if (IS_ENABLED(CONFIG_DEBUG_VM))
		dump_page(map_page, "map_page after being discarded");

	/* done */
	goto out_finalize;

out_err:
	/* get_user_pages_remote() incremented page reference count */
	if (req_page != NULL)
		put_page(req_page);

out_finalize:
	/* release semaphores in reverse order */
	up_write(&map_mm->mmap_sem);
	up_write(&req_mm->mmap_sem);

	return result;
}

int kvmi_host_mem_map(struct kvm_vcpu *vcpu, gva_t tkn_gva,
		      gpa_t req_gpa, gpa_t map_gpa)
{
	int result = 0;
	struct kvm *target_kvm;

	gfn_t req_gfn;
	hva_t req_hva;
	struct mm_struct *req_mm;

	gfn_t map_gfn;
	hva_t map_hva;
	struct mm_struct *map_mm = vcpu->kvm->mm;

	kvm_debug("kvmi: mapping request req_gpa %016llx, map_gpa %016llx\n",
		  req_gpa, map_gpa);

	/* get the struct kvm * corresponding to the token */
	target_kvm = find_machine_at(vcpu, tkn_gva);
	if (IS_ERR_VALUE(target_kvm)) {
		return PTR_ERR(target_kvm);
	} else if (target_kvm == NULL) {
		kvm_err("kvmi: unable to find target machine\n");
		return -ENOENT;
	}
	kvm_get_kvm(target_kvm);
	req_mm = target_kvm->mm;

	/* translate source addresses */
	req_gfn = gpa_to_gfn(req_gpa);
	req_hva = gfn_to_hva_safe(target_kvm, req_gfn);
	if (kvm_is_error_hva(req_hva)) {
		kvm_err("kvmi: invalid req HVA %016lx\n", req_hva);
		result = -EFAULT;
		goto out;
	}

	kvm_debug("kvmi: req_gpa %016llx, req_gfn %016llx, req_hva %016lx\n",
		  req_gpa, req_gfn, req_hva);

	/* translate destination addresses */
	map_gfn = gpa_to_gfn(map_gpa);
	map_hva = gfn_to_hva_safe(vcpu->kvm, map_gfn);
	if (kvm_is_error_hva(map_hva)) {
		kvm_err("kvmi: invalid map HVA %016lx\n", map_hva);
		result = -EFAULT;
		goto out;
	}

	kvm_debug("kvmi: map_gpa %016llx, map_gfn %016llx, map_hva %016lx\n",
		map_gpa, map_gfn, map_hva);

	/* go to step 2 */
	result = kvmi_map_action(req_mm, req_hva, map_mm, map_hva);
	if (IS_ERR_VALUE((long)result))
		goto out;

	/* add mapping to list */
	result = add_to_list(map_gpa, target_kvm, req_gpa);
	if (IS_ERR_VALUE((long)result))
		goto out;

	/* all fine */
	kvm_debug("kvmi: mapping of req_gpa %016llx successful\n", req_gpa);

out:
	/* mandatory dec refernce count */
	kvm_put_kvm(target_kvm);

	return result;
}


static int restore_rmap(struct vm_area_struct *map_vma, hva_t map_hva,
			struct page *req_page, struct page *new_page)
{
	int result;

	/* decouple links to anon_vmas */
	unlink_anon_vmas(map_vma);
	map_vma->anon_vma = NULL;

	/* allocate new anon_vma */
	result = anon_vma_prepare(map_vma);
	if (IS_ERR_VALUE((long)result))
		return result;

	lock_page(new_page);
	page_add_new_anon_rmap(new_page, map_vma, map_hva, false);
	unlock_page(new_page);

	/* decrease req_page mapcount */
	atomic_dec(&req_page->_mapcount);

	return 0;
}

static int host_unmap_fix_ptes(struct vm_area_struct *map_vma, hva_t map_hva,
			       struct page *new_page)
{
	struct mm_struct *map_mm = map_vma->vm_mm;
	pmd_t *pmd;
	pte_t *ptep;
	spinlock_t *ptl;
	pte_t newpte;

	unsigned long mmun_start;
	unsigned long mmun_end;

	/* page replacing code */
	pmd = mm_find_pmd(map_mm, map_hva);
	if (!pmd)
		return -EFAULT;

	mmun_start = map_hva;
	mmun_end = map_hva + PAGE_SIZE;
	mmu_notifier_invalidate_range_start(map_mm, mmun_start, mmun_end);

	ptep = pte_offset_map_lock(map_mm, pmd, map_hva, &ptl);

	newpte = mk_pte(new_page, map_vma->vm_page_prot);
	newpte = pte_set_flags(newpte, pte_flags(*ptep));

	/* clear cache & MMU notifier entries */
	flush_cache_page(map_vma, map_hva, pte_pfn(*ptep));
	ptep_clear_flush_notify(map_vma, map_hva, ptep);
	set_pte_at_notify(map_mm, map_hva, ptep, newpte);

	pte_unmap_unlock(ptep, ptl);

	mmu_notifier_invalidate_range_end(map_mm, mmun_start, mmun_end);

	return 0;
}

static int kvmi_unmap_action(struct mm_struct *req_mm,
			     struct mm_struct *map_mm, hva_t map_hva)
{
	struct vm_area_struct *map_vma;
	struct page *req_page = NULL;
	struct page *new_page = NULL;

	int result;

	/* VMAs will be modified */
	down_write(&req_mm->mmap_sem);
	down_write(&map_mm->mmap_sem);

	/* find destination VMA for mapping */
	map_vma = find_vma(map_mm, map_hva);
	if (map_vma == NULL) {
		result = -ENOENT;
		kvm_err("kvmi: no local VMA found for unmapping\n");
		goto out_err;
	}

	/* find (not get) page mapped to destination address */
	req_page = follow_page(map_vma, map_hva, 0);
	if (IS_ERR_VALUE(req_page)) {
		result = PTR_ERR(req_page);
		kvm_err("kvmi: follow_page() failed with result %d\n", result);
		goto out_err;
	} else if (req_page == NULL) {
		result = -ENOENT;
		kvm_err("kvmi: follow_page() returned no page\n");
		goto out_err;
	}

	if (IS_ENABLED(CONFIG_DEBUG_VM))
		dump_page(req_page, "req_page before decoupling");

	/* Returns NULL when no page can be allocated. */
	new_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, map_vma, map_hva);
	if (new_page == NULL) {
		result = -ENOMEM;
		goto out_err;
	}

	if (IS_ENABLED(CONFIG_DEBUG_VM))
		dump_page(new_page, "new_page after allocation");

	/* should fix the rmap tree */
	result = restore_rmap(map_vma, map_hva, req_page, new_page);
	if (IS_ERR_VALUE((long)result))
		goto out_err;

	if (IS_ENABLED(CONFIG_DEBUG_VM))
		dump_page(req_page, "req_page after decoupling");

	/* page table fixing here */
	result = host_unmap_fix_ptes(map_vma, map_hva, new_page);
	if (IS_ERR_VALUE((long)result))
		goto out_err;

	if (IS_ENABLED(CONFIG_DEBUG_VM))
		dump_page(new_page, "new_page after unmapping");

	goto out_finalize;

out_err:
	if (new_page != NULL)
		put_page(new_page);

out_finalize:
	/* reference count was inc during get_user_pages_remote() */
	if (req_page != NULL) {
		put_page(req_page);

		if (IS_ENABLED(CONFIG_DEBUG_VM))
			dump_page(req_page, "req_page after release");
	}

	/* release semaphores in reverse order */
	up_write(&map_mm->mmap_sem);
	up_write(&req_mm->mmap_sem);

	return result;
}

int kvmi_host_mem_unmap(struct kvm_vcpu *vcpu, gpa_t map_gpa)
{
	struct kvm *target_kvm;
	struct mm_struct *req_mm;

	struct host_map *map;
	int result;

	gfn_t map_gfn;
	hva_t map_hva;
	struct mm_struct *map_mm = vcpu->kvm->mm;

	kvm_debug("kvmi: unmap request for map_gpa %016llx\n", map_gpa);

	/* get the struct kvm * corresponding to map_gpa */
	map = extract_from_list(map_gpa);
	if (map == NULL) {
		kvm_err("kvmi: map_gpa %016llx not mapped\n", map_gpa);
		return -ENOENT;
	}
	target_kvm = map->machine;
	kvm_get_kvm(target_kvm);
	req_mm = target_kvm->mm;

	kvm_debug("kvmi: req_gpa %016llx of machine %016lx mapped in map_gpa %016llx\n",
		  map->req_gpa, (unsigned long) map->machine, map->map_gpa);

	/* address where we did the remapping */
	map_gfn = gpa_to_gfn(map_gpa);
	map_hva = gfn_to_hva_safe(vcpu->kvm, map_gfn);
	if (kvm_is_error_hva(map_hva)) {
		result = -EFAULT;
		kvm_err("kvmi: invalid HVA %016lx\n", map_hva);
		goto out;
	}

	kvm_debug("kvmi: map_gpa %016llx, map_gfn %016llx, map_hva %016lx\n",
		  map_gpa, map_gfn, map_hva);

	/* go to step 2 */
	result = kvmi_unmap_action(req_mm, map_mm, map_hva);
	if (IS_ERR_VALUE((long)result))
		goto out;

	kvm_debug("kvmi: unmap of map_gpa %016llx successful\n", map_gpa);

out:
	kvm_put_kvm(target_kvm);

	/* remove entry whatever happens above */
	remove_entry(map);

	return result;
}

void kvmi_mem_destroy_vm(struct kvm *kvm)
{
	kvm_debug("kvmi: machine %016lx was torn down\n",
		(unsigned long) kvm);

	remove_vm_from_list(kvm);
	remove_vm_token(kvm);
}

/*
 * TODO: don't make a module out of this file.
 * Call this function from kvmi_init().
 */
int kvm_intro_host_init(void)
{
	/* token database */
	INIT_LIST_HEAD(&token_list);
	spin_lock_init(&token_lock);

	/* mapping database */
	INIT_LIST_HEAD(&mapping_list);
	spin_lock_init(&mapping_lock);

	kvm_info("kvmi: initialized host memory introspection\n");

	return 0;
}

void kvm_intro_host_exit(void)
{
	// ...
}

module_init(kvm_intro_host_init)
module_exit(kvm_intro_host_exit)
