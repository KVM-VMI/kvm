// SPDX-License-Identifier: GPL-2.0
/*
 * Remote memory mapping.
 *
 * Copyright (C) 2017-2019 Bitdefender S.R.L.
 *
 * Author:
 *   Mircea Cirjaliu <mcirjaliu@bitdefender.com>
 */
#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/rmap.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/oom.h>
#include <linux/huge_mm.h>
#include <linux/mmu_notifier.h>
#include <linux/sched/mm.h>
#include <linux/interval_tree_generic.h>
#include <linux/hashtable.h>
#include <linux/refcount.h>
#include <linux/debugfs.h>
#include <linux/miscdevice.h>
#include <linux/remote_mapping.h>
#include <uapi/linux/remote_mapping.h>

#include "internal.h"

#define ASSERT(exp) BUG_ON(!(exp))
#define BUSY_BIT 0
#define MAPPED_BIT 1

#define TDB_HASH_BITS 4
#define CDB_HASH_BITS 2

static int mm_remote_do_unmap(struct mm_struct *map_mm, unsigned long map_hva);
static int mm_remote_do_unmap_target(struct page_db *pdb);
static int mm_remote_make_stale(struct page_db *pdb);

static void mm_remote_db_target_release(struct target_db *tdb);
static void mm_remote_db_client_release(struct client_db *cdb);

static void tdb_release(struct mmu_notifier *mn, struct mm_struct *mm);
static void cdb_release(struct mmu_notifier *mn, struct mm_struct *mm);
static void target_db_free_delayed(struct mmu_notifier *mn);
static void client_db_free_delayed(struct mmu_notifier *mn);

static const struct mmu_notifier_ops tdb_notifier_ops = {
	.release = tdb_release,
	.free_notifier = target_db_free_delayed,
};

static const struct mmu_notifier_ops cdb_notifier_ops = {
	.release = cdb_release,
	.free_notifier = client_db_free_delayed,
};

static DEFINE_HASHTABLE(tdb_hash, TDB_HASH_BITS);
static DEFINE_SPINLOCK(tdb_lock);

static DEFINE_HASHTABLE(cdb_hash, CDB_HASH_BITS);
static DEFINE_SPINLOCK(cdb_lock);

static struct kmem_cache *pdb_cache;
static atomic_t pdb_count = ATOMIC_INIT(0);
static atomic_t map_count = ATOMIC_INIT(0);
static atomic_t rpg_count = ATOMIC_INIT(0);

static atomic_t stat_empty_pte = ATOMIC_INIT(0);
static atomic_t stat_mapped_pte = ATOMIC_INIT(0);
static atomic_t stat_swap_pte = ATOMIC_INIT(0);
static atomic_t stat_refault = ATOMIC_INIT(0);

static struct dentry *mm_remote_debugfs_dir;

static void target_db_init(struct target_db *tdb)
{
	tdb->mn.ops = &tdb_notifier_ops;
	refcount_set(&tdb->refcnt, 0);

	tdb->client = NULL;
	INIT_LIST_HEAD(&tdb->pages_list);
	spin_lock_init(&tdb->lock);
}

static struct target_db *target_db_alloc(void)
{
	struct target_db *tdb;

	tdb = kzalloc(sizeof(*tdb), GFP_KERNEL);
	if (tdb != NULL)
		target_db_init(tdb);

	return tdb;
}

static void target_db_free(struct target_db *tdb)
{
	ASSERT(refcount_read(&tdb->refcnt) == 0);
	ASSERT(list_empty(&tdb->pages_list));

	kfree(tdb);
}

static void target_db_insert(struct target_db *tdb, struct page_db *pdb)
{
	list_add(&pdb->target_link, &tdb->pages_list);
}

static bool target_db_empty(const struct target_db *tdb)
{
	return list_empty(&tdb->pages_list);
}

static void target_db_remove(struct target_db *tdb, struct page_db *pdb)
{
	list_del(&pdb->target_link);
}

static void target_db_free_delayed(struct mmu_notifier *mn)
{
	struct target_db *tdb = container_of(mn, struct target_db, mn);

	pr_debug("%s: for mm %016lx\n", __func__, (unsigned long)tdb->mm);

	target_db_free(tdb);
}

static void target_db_put(struct target_db *tdb)
{
	if (refcount_dec_and_test(&tdb->refcnt)) {
		pr_debug("%s: mm %016lx\n", __func__, (unsigned long)tdb->mm);

		spin_lock(&tdb_lock);
		hash_del(&tdb->db_link);
		spin_unlock(&tdb_lock);

		mm_remote_db_target_release(tdb);

		ASSERT(target_db_empty(tdb));

		mmu_notifier_put(&tdb->mn);
	}
}

static struct target_db *target_db_lookup(const struct mm_struct *mm)
{
	struct target_db *tdb;

	spin_lock(&tdb_lock);

	hash_for_each_possible(tdb_hash, tdb, db_link, (unsigned long)mm)
		if (tdb->mm == mm && refcount_inc_not_zero(&tdb->refcnt))
			break;

	spin_unlock(&tdb_lock);

	return tdb;
}

static struct target_db *target_db_lookup_or_add(struct mm_struct *mm)
{
	struct target_db *tdb, *allocated;
	bool found = false;
	int result;

	allocated = target_db_alloc();	/* may be NULL */

	spin_lock(&tdb_lock);

	hash_for_each_possible(tdb_hash, tdb, db_link, (unsigned long)mm)
		if (tdb->mm == mm && refcount_inc_not_zero(&tdb->refcnt)) {
			found = true;
			break;
		}

	if (!found && allocated != NULL) {
		tdb = allocated;
		allocated = NULL;

		tdb->mm = mm;
		hash_add(tdb_hash, &tdb->db_link, (unsigned long)mm);
		refcount_set(&tdb->refcnt, 1);
	}

	spin_unlock(&tdb_lock);

	if (allocated != NULL)
		target_db_free(allocated);

	if (found || tdb == NULL)
		return tdb;

	/*
	 * register a mmu notifier when adding this entry to the list - at this
	 * point other threads may already have hold of this tdb
	 */
	result = mmu_notifier_register(&tdb->mn, mm);
	if (IS_ERR_VALUE((long) result)) {
		pr_err("mmu_notifier_register() failed: %d\n", result);

		target_db_put(tdb);
		return ERR_PTR((long) result);
	}

	pr_debug("%s: new entry for mm %016lx\n",
		__func__, (unsigned long)tdb->mm);

	refcount_inc(&tdb->refcnt);
	return tdb;
}

static void client_db_init(struct client_db *cdb)
{
	cdb->mm = NULL;
	INIT_HLIST_NODE(&cdb->db_link);

	cdb->mn.ops = &cdb_notifier_ops;
	refcount_set(&cdb->refcnt, 0);

	cdb->pseudo = NULL;
}

static struct client_db *client_db_alloc(void)
{
	struct client_db *cdb;

	cdb = kzalloc(sizeof(*cdb), GFP_KERNEL);
	if (cdb != NULL)
		client_db_init(cdb);

	return cdb;
}

static void client_db_free(struct client_db *cdb)
{
	ASSERT(refcount_read(&cdb->refcnt) == 0);

	kfree(cdb);
}

static void client_db_free_delayed(struct mmu_notifier *mn)
{
	struct client_db *cdb = container_of(mn, struct client_db, mn);

	pr_debug("%s: mm %016lx\n", __func__, (unsigned long)cdb->mm);

	client_db_free(cdb);
}

static void client_db_put(struct client_db *cdb)
{
	if (refcount_dec_and_test(&cdb->refcnt)) {
		pr_debug("%s: mm %016lx\n", __func__, (unsigned long)cdb->mm);

		spin_lock(&cdb_lock);
		hash_del(&cdb->db_link);
		spin_unlock(&cdb_lock);

		mm_remote_db_client_release(cdb);

		mmu_notifier_put(&cdb->mn);
	}
}

static struct client_db *client_db_lookup(const struct mm_struct *mm)
{
	struct client_db *cdb;

	spin_lock(&cdb_lock);

	hash_for_each_possible(cdb_hash, cdb, db_link, (unsigned long)mm)
		if (cdb->mm == mm && refcount_inc_not_zero(&cdb->refcnt))
			break;

	spin_unlock(&cdb_lock);

	return cdb;
}

// TODO: each mapping request by direct kernel interface calls this function
// to find its mm association. Temporary allocating a struct client_db for each
// mapping attempt may pose a performance problem.
static struct client_db *client_db_lookup_or_add(struct mm_struct *mm)
{
	struct client_db *cdb, *allocated;
	bool found = false;
	int result;

	allocated = client_db_alloc();	/* may be NULL */

	spin_lock(&cdb_lock);

	hash_for_each_possible(cdb_hash, cdb, db_link, (unsigned long)mm)
		if (cdb->mm == mm && refcount_inc_not_zero(&cdb->refcnt)) {
			found = true;
			break;
		}

	if (!found && allocated != NULL) {
		cdb = allocated;
		allocated = NULL;

		cdb->mm = mm;
		hash_add(cdb_hash, &cdb->db_link, (unsigned long)mm);
		refcount_set(&cdb->refcnt, 1);
	}

	spin_unlock(&cdb_lock);

	if (allocated != NULL)
		client_db_free(allocated);

	if (found || cdb == NULL)
		return cdb;

	/*
	 * register a mmu notifier when adding this entry to the list - at this
	 * point other threads may already have hold of this cdb
	 */
	result = mmu_notifier_register(&cdb->mn, mm);
	if (IS_ERR_VALUE((long)result)) {
		pr_err("mmu_notifier_register() failed: %d\n", result);

		client_db_put(cdb);
		return ERR_PTR((long)result);
	}

	pr_debug("%s: new entry for mm %016lx\n",
		__func__, (unsigned long)cdb->mm);

	refcount_inc(&cdb->refcnt);
	return cdb;
}

KEYED_RB_TREE(client_db_hva, struct file_db, rb_root,
	struct page_db, file_link, map_hva)

static void file_db_init(struct file_db *fdb)
{
	fdb->cdb = NULL;

	spin_lock_init(&fdb->lock);
	fdb->rb_root = RB_ROOT;
}

static struct file_db *file_db_alloc(void)
{
	struct file_db *fdb;

	fdb = kmalloc(sizeof(*fdb), GFP_KERNEL);
	if (fdb != NULL)
		file_db_init(fdb);

	return fdb;
}

static void file_db_free(struct file_db *fdb)
{
	ASSERT(client_db_hva_empty(fdb));

	kfree(fdb);
}

static struct file_db *client_db_pseudo_file(struct client_db *cdb)
{
	struct file_db *allocated;

	if (cdb->pseudo == NULL) {
		allocated = file_db_alloc();
		if (allocated != NULL)
			allocated->cdb = cdb;
		if (cmpxchg(&cdb->pseudo, NULL, allocated))
			file_db_free(allocated);
	}

	return cdb->pseudo;
}

static struct page_db *page_db_alloc(void)
{
	struct page_db *result;

	result = kmem_cache_alloc(pdb_cache, GFP_KERNEL);
	if (result == NULL)
		return NULL;

	memset(result, 0, sizeof(*result));

	atomic_inc(&pdb_count);

	return result;
}

static void page_db_free(struct page_db *pdb)
{
	kmem_cache_free(pdb_cache, pdb);

	BUG_ON(atomic_add_negative(-1, &pdb_count));
}

static void page_db_put(struct page_db *pdb)
{
	if (refcount_dec_and_test(&pdb->refcnt)) {

		/* this case is possible if both target and client are
		 * OOM-killed in quick succession and the release functions
		 * can't get to the remote mapped page
		 */
		if (pdb->map_anon_vma)
			put_anon_vma(pdb->map_anon_vma);
		if (pdb->req_anon_vma)
			put_anon_vma(pdb->req_anon_vma);

		page_db_free(pdb);
	}
}

static void page_db_release(struct page_db *pdb)
{
	clear_bit(BUSY_BIT, (unsigned long *)&pdb->flags);
	/* see comments of wake_up_bit(), set_bit() is atomic */
	smp_mb__after_atomic();
	wake_up_bit(&pdb->flags, BUSY_BIT);
}

/* Reserve a mapping entry indexed by map_hva in the file database. */
static struct page_db *
page_db_reserve(struct file_db *fdb, struct mm_struct *req_mm,
	unsigned long req_hva, unsigned long map_hva)
{
	struct page_db *pdb;

	pdb = page_db_alloc();
	if (unlikely(pdb == NULL))
		return ERR_PTR(-ENOMEM);

	/* fill pdb */
	pdb->target = req_mm;
	pdb->req_hva = req_hva;
	pdb->map_hva = map_hva;
	refcount_set(&pdb->refcnt, 1);
	__set_bit(BUSY_BIT, (unsigned long *)&pdb->flags);

	/* insert mapping entry into the client if not already there */
	spin_lock(&fdb->lock);

	if (likely(client_db_hva_insert(fdb, pdb)))
		refcount_inc(&pdb->refcnt);
	else {
		page_db_free(pdb);
		pdb = ERR_PTR(-EALREADY);
	}

	spin_unlock(&fdb->lock);

	return pdb;
}

/* Reverse of page_db_reserve(), to be called in case of error. */
static void
page_db_unreserve(struct file_db *fdb, struct page_db *pdb)
{
	spin_lock(&fdb->lock);

	client_db_hva_remove(fdb, pdb);
	page_db_put(pdb);

	spin_unlock(&fdb->lock);

	page_db_release(pdb);
	page_db_put(pdb);
}

/* Marks as mapped & drops reference. */
static void
page_db_got_mapped(struct page_db *pdb)
{
	__set_bit(MAPPED_BIT, (unsigned long *)&pdb->flags);

	page_db_release(pdb);
	page_db_put(pdb);
}

/* Gets exclusive access for unmapping. */
static struct page_db *
page_db_begin_unmap(struct file_db *fdb, unsigned long map_hva)
{
	struct page_db *pdb;
	int result;

	spin_lock(&fdb->lock);

	pdb = client_db_hva_search(fdb, map_hva);
	if (likely(pdb != NULL))
		refcount_inc(&pdb->refcnt);

	spin_unlock(&fdb->lock);

	if (pdb == NULL)
		return NULL;

retry:
	result = wait_on_bit((unsigned long *)&pdb->flags, BUSY_BIT,
			     TASK_KILLABLE);
	/* non-zero if interrupted by a signal */
	if (unlikely(result != 0))
		return ERR_PTR(-EINTR);

	/* try set bit & spin if failed */
	if (test_and_set_bit(BUSY_BIT, (unsigned long *)&pdb->flags))
		goto retry;

	return pdb;
}

/* Marks as unmapped, removes from tree & drops reference. */
static void
page_db_end_unmap(struct file_db *fdb, struct page_db *pdb)
{
	__clear_bit(MAPPED_BIT, (unsigned long *)&pdb->flags);

	spin_lock(&fdb->lock);

	client_db_hva_remove(fdb, pdb);
	page_db_put(pdb);

	spin_unlock(&fdb->lock);

	page_db_release(pdb);
	page_db_put(pdb);
}

static int
page_db_add_target(struct page_db *pdb, struct mm_struct *target,
		   struct mm_struct *client)
{
	struct target_db *tdb;
	int result = 0;

	/*
	 * returns a valid pointer or an error value, never NULL
	 * also gets reference to entry
	 */
	tdb = target_db_lookup_or_add(target);
	if (IS_ERR_VALUE(tdb))
		return PTR_ERR(tdb);

	/* target-side locking */
	spin_lock(&tdb->lock);

	/* check that target is not introspected by someone else */
	if (tdb->client != NULL && tdb->client != client)
		result = -EINVAL;
	else {
		tdb->client = client;
		target_db_insert(tdb, pdb);
	}

	spin_unlock(&tdb->lock);

	target_db_put(tdb);

	return result;
}

static int
page_db_remove_target(struct page_db *pdb)
{
	struct target_db *tdb;
	int result = 0;

	/* find target entry in the database */
	tdb = target_db_lookup(pdb->target);
	if (tdb == NULL)
		return -ENOENT;

	/* target-side locking */
	spin_lock(&tdb->lock);

	/* remove mapping from target */
	target_db_remove(tdb, pdb);

	/* clear the client if no more mappings */
	if (target_db_empty(tdb)) {
		tdb->client = NULL;
		pr_debug("%s: all mappings gone for target mm %016lx\n",
			__func__, (unsigned long)pdb->target);
	}

	spin_unlock(&tdb->lock);

	target_db_put(tdb);

	return result;
}

/*
 * Clear all the links to a target at once.
 */
static void mm_remote_db_cleanup_target(struct client_db *cdb,
					struct target_db *tdb)
{
	struct page_db *pdb, *npdb;

	/* if we ended up here the target must be introspected */
	ASSERT(tdb->client != NULL);
	tdb->client = NULL;

	/*
	 * walk the tree & clear links to target - this function is serialized
	 * with respect to the main loop in mm_remote_db_client_release() so
	 * there will be no race on pdb->target
	 */
	list_for_each_entry_safe(pdb, npdb, &tdb->pages_list, target_link) {
		if (mm_is_oom_victim(cdb->mm))
			mm_remote_do_unmap_target(pdb);

		list_del(&pdb->target_link);
		pdb->target = NULL;
	}
}

/*
 * A client file is closing. No race with operations of file is possible.
 */
static void mm_remote_db_file_release(struct file_db *fdb)
{
	struct client_db *cdb = fdb->cdb;
	struct page_db *pdb, *npdb;
	struct target_db *tdb;

	if (!client_db_hva_empty(fdb))
		pr_debug("%s: client file %016lx has mappings\n",
			__func__, (unsigned long)fdb);

	/* iterate the tree of mappings */
	rbtree_postorder_for_each_entry_safe(pdb, npdb, &fdb->rb_root, file_link) {
		/* pdb->target is cleared in the func above, store in var */
		struct mm_struct *req_mm = pdb->target;

		/* see comments in function above */
		if (req_mm == NULL)
			goto just_free;

		/* pin target to avoid race with mm_remote_db_target_release() */
		if (mmget_not_zero(req_mm)) {

			/* pin entry for target - maybe it has been released */
			tdb = target_db_lookup(req_mm);
			if (tdb != NULL) {
				/* see comments of this function */
				mm_remote_db_cleanup_target(cdb, tdb);

				/* unpin entry for target */
				target_db_put(tdb);
			}

			mmput(req_mm);
		}

	just_free:
		/* invalidate links to client */
		RB_CLEAR_NODE(&pdb->file_link);

		if (!mm_is_oom_victim(cdb->mm))
			mm_remote_do_unmap(cdb->mm, pdb->map_hva);

		page_db_put(pdb);
	}

	/* clear root of tree */
	fdb->rb_root = RB_ROOT;
}

/*
 * The client is closing. This means the normal mapping/unmapping logic
 * does not work anymore. No more locking needed.
 */
static void mm_remote_db_client_release(struct client_db *cdb)
{
	struct file_db *fdb = cdb->pseudo;

	if (fdb == NULL)
		return;

	pr_debug("%s: client %016lx has special file\n",
		__func__, (unsigned long) cdb);

	mm_remote_db_file_release(fdb);
}

/*
 * Called when a target exits and the page must be marked as stale and the
 * target-side anon-vma released.
 * This function will not race with mm_remote_remap(), since a reference to the
 * target MM is taken before mapping being done.
 * This function may race with mm_remote_do_unmap(), so a check must be
 * done under page lock to make sure the page is still remote mapped.
 * After this is run, the pages are still remote mapped pages, but the rmap
 * only points to the client.
 */
static int mm_remote_make_stale(struct page_db *pdb)
{
	struct mm_struct *req_mm = pdb->target;
	struct vm_area_struct *req_vma;
	struct page *req_page;
	int result = 0;

	/* this allows faulting to happen */
	down_read(&req_mm->mmap_sem);

	/* find VMA containing address */
	req_vma = find_vma(req_mm, pdb->req_hva);
	if (unlikely(req_vma == NULL)) {
		result = -ENOENT;
		pr_err("no remote VMA found for stalling\n");
		goto out_unlock;
	}

	/* should be available & unevictable */
	req_page = follow_page(req_vma, pdb->req_hva, FOLL_MIGRATION | FOLL_GET);
	if (IS_ERR_VALUE(req_page)) {
		result = PTR_ERR(req_page);
		pr_err("follow_page() failed: %d\n", result);
		goto out_unlock;
	} else if (unlikely(req_page == NULL)) {
		result = -ENOENT;
		pr_err("follow_page() returned no page\n");
		goto out_unlock;
	}

	/* access to RMAP components of PDB can only be done under page lock */
	lock_page(req_page);

	if (likely(PageRemote(req_page))) {
		ASSERT(pdb->req_anon_vma == req_vma->anon_vma);
		/* just release target anon_vma - the page will be temporarily
		 * left with increased mapcount & refcount, which will be
		 * decremented when the page is unmapped from the target mm
		 */
		put_anon_vma(pdb->req_anon_vma);
		pdb->req_anon_vma = NULL;
	}

	unlock_page(req_page);

	put_page(req_page);	/* follow_page(... FOLL_GET) */

out_unlock:
	up_read(&req_mm->mmap_sem);

	return result;
}

static int mm_remote_make_stale_client(struct mm_struct *map_mm,
				       struct page_db *pdb)
{
	struct vm_area_struct *map_vma;
	struct page *req_page;

	int result = 0;

	down_read(&map_mm->mmap_sem);

	map_vma = find_vma(map_mm, pdb->map_hva);
	if (unlikely(map_vma == NULL)) {
		result = -ENOENT;
		pr_err("no client VMA found for stalling\n");
		goto out_unlock;
	}

	/* should be available & unevictable */
	req_page = follow_page(map_vma, pdb->map_hva, FOLL_MIGRATION | FOLL_GET);
	if (IS_ERR_VALUE(req_page)) {
		result = PTR_ERR(req_page);
		pr_err("follow_page() failed: %d\n", result);
		goto out_unlock;
	} else if (unlikely(req_page == NULL)) {
		result = -ENOENT;
		pr_err("follow_page() returned no page\n");
		goto out_unlock;
	}

	/* access to RMAP components of PDB can only be done under page lock */
	lock_page(req_page);

	if (likely(PageRemote(req_page))) {
		/* just release target anon_vma - the page will be temporarily
		 * left with increased mapcount & refcount, which will be
		 * decremented when the page is unmapped from the target mm
		 */
		put_anon_vma(pdb->req_anon_vma);
		pdb->req_anon_vma = NULL;
	}

	unlock_page(req_page);

	put_page(req_page);	/* follow_page(... FOLL_GET) */

out_unlock:
	up_read(&map_mm->mmap_sem);

	return result;
}

/*
 * The target MM is closing. This means the pages are unmapped by the default
 * kernel logic on the target side, but we must mark the entries as stale.
 * This function won't race with the mapping function since we get here
 * on target MM teardown and the mapping function won't be able to get a
 * reference to the target MM.
 * This function may race with the unmapping function, but
 * access will be done only on the target-side components.
 */
static void mm_remote_db_target_release(struct target_db *tdb)
{
	struct mm_struct *map_mm;
	struct page_db *pdb, *npdb;

	/* no client, nothing to do */
	if (tdb->client == NULL) {
		ASSERT(target_db_empty(tdb));
		return;
	}

	map_mm = tdb->client;
	tdb->client = NULL;

	/* if the target is killed by OOM, try to pin the client */
	if (mm_is_oom_victim(tdb->mm) && !mmget_not_zero(map_mm)) {
		/* out of luck, just unlink from the list */
		list_for_each_entry_safe(pdb, npdb, &tdb->pages_list, target_link) {
			list_del(&pdb->target_link);
			pdb->target = NULL;
		}

		return;
	}

	/*
	 * all the entries in this tree must be made stale,
	 * but not removed from the client tree
	 */
	list_for_each_entry_safe(pdb, npdb, &tdb->pages_list, target_link) {
		if (!mm_is_oom_victim(tdb->mm))
			mm_remote_make_stale(pdb);
		else
			mm_remote_make_stale_client(map_mm, pdb);

		list_del(&pdb->target_link);
		pdb->target = NULL;
	}

	/* client has been pinned before */
	if (mm_is_oom_victim(tdb->mm))
		mmput(map_mm);
}

static void tdb_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	struct target_db *tdb = container_of(mn, struct target_db, mn);

	pr_debug("%s: mm %016lx\n", __func__, (unsigned long)mm);

	/* at this point other threads may already have hold of this tdb */
	target_db_put(tdb);
}

static void cdb_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	struct client_db *cdb = container_of(mn, struct client_db, mn);

	pr_debug("%s: mm %016lx\n", __func__, (unsigned long)mm);

	/* at this point other threads may already have hold of this cdb */
	client_db_put(cdb);
}

static void mm_remote_page_unevictable(struct page *page)
{
	VM_BUG_ON_PAGE(!PageLocked(page), page);

	if (!isolate_lru_page(page))
		putback_lru_page(page);
}

static void mm_remote_page_evictable(struct page *page)
{
	VM_BUG_ON_PAGE(!PageLocked(page), page);

	if (!isolate_lru_page(page))
		putback_lru_page(page);
	else {
		if (PageUnevictable(page))
			count_vm_event(UNEVICTABLE_PGSTRANDED);
	}
}

void rmap_walk_remote(struct page *page, struct rmap_walk_control *rwc)
{
	struct page_db *pdb;
	struct anon_vma *anon_vma;
	struct anon_vma_chain *avc;
	struct vm_area_struct *vma;
	pgoff_t pgoff_start, pgoff_end;
	unsigned long address;

	VM_BUG_ON_PAGE(!PageRemote(page), page);
	VM_BUG_ON_PAGE(!PageLocked(page), page);

	pdb = (void *)((unsigned long)page->mapping & ~PAGE_MAPPING_FLAGS);

	/* iterate on original anon_vma */
	anon_vma = pdb->req_anon_vma;
	if (anon_vma != NULL) {
		anon_vma_lock_read(anon_vma);
		pgoff_start = page_to_pgoff(page);
		pgoff_end = pgoff_start + hpage_nr_pages(page) - 1;
		anon_vma_interval_tree_foreach(avc, &anon_vma->rb_root,
					       pgoff_start, pgoff_end) {
			vma = avc->vma;
			address = vma_address(page, vma);

			cond_resched();

			if (rwc->invalid_vma && rwc->invalid_vma(vma, rwc->arg))
				continue;

			if (!rwc->rmap_one(page, vma, address, rwc->arg))
				break;

			if (rwc->done && rwc->done(page))
				break;
		}
		anon_vma_unlock_read(anon_vma);
	}

	/* iterare on client anon_vma */
	anon_vma = pdb->map_anon_vma;
	if (anon_vma != NULL) {
		anon_vma_lock_read(anon_vma);
		anon_vma_interval_tree_foreach(avc, &anon_vma->rb_root,
					       0, ULONG_MAX) {
			vma = avc->vma;
			address = pdb->map_hva;

			cond_resched();

			if (rwc->invalid_vma && rwc->invalid_vma(vma, rwc->arg))
				continue;

			if (!rwc->rmap_one(page, vma, address, rwc->arg))
				break;

			if (rwc->done && rwc->done(page))
				break;
		}
		anon_vma_unlock_read(anon_vma);
	}
}

static int mm_remote_invalidate_pte(struct vm_area_struct *map_vma,
	unsigned long map_hva, pmd_t *map_pmd, struct page *map_page)
{
	struct mm_struct *map_mm = map_vma->vm_mm;
	struct mmu_notifier_range range;
	unsigned long mmun_start;
	unsigned long mmun_end;
	pte_t *ptep;
	spinlock_t *ptl;
	swp_entry_t entry;
	int result = 0;

	mmun_start = map_hva;
	mmun_end = map_hva + PAGE_SIZE;
	mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0,
				map_vma, map_mm, mmun_start, mmun_end);
	mmu_notifier_invalidate_range_start(&range);

	ptep = pte_offset_map_lock(map_mm, map_pmd, map_hva, &ptl);

	/* remove reverse mapping - the caller needs to hold the pte lock */
	if (likely(map_page != NULL)) {
		page_remove_rmap(map_page, false);

		/* the zero_page is not anonymous */
		if (!is_zero_pfn(pte_pfn(*ptep)))
			dec_mm_counter(map_mm, MM_ANONPAGES);

		/* clear old PTE entry */
		flush_cache_page(map_vma, map_hva, pte_pfn(*ptep));
		ptep_clear_flush_notify(map_vma, map_hva, ptep);

		atomic_inc(&stat_mapped_pte);
	} else {
		/* fresh PTE or has been cleared before */
		if (likely(pte_none(*ptep))) {
			atomic_inc(&stat_empty_pte);
			goto out_unlock;
		}

		/* a page was faulted in after follow_page() returned NULL */
		if (unlikely(pte_present(*ptep))) {
			atomic_inc(&stat_refault);
			result = -EAGAIN;
			goto out_unlock;
		}

		/* must be swap entry */
		entry = pte_to_swp_entry(*ptep);
		/* follow_page(... | FOLL_MIGRATION | ...) */
		ASSERT(!is_migration_entry(entry));
		free_swap_and_cache(entry);
		ptep_clear_flush(map_vma, map_hva, ptep);

		atomic_inc(&stat_swap_pte);
	}

out_unlock:
	pte_unmap_unlock(ptep, ptl);

	mmu_notifier_invalidate_range_end(&range);

	return result;
}

static int mm_remote_install_pte(struct vm_area_struct *map_vma,
	unsigned long map_hva, pmd_t *map_pmd, struct page *req_page)
{
	struct mm_struct *map_mm = map_vma->vm_mm;
	pte_t pte, *ptep;
	spinlock_t *ptl;
	int result = 0;

	ptep = pte_offset_map_lock(map_mm, map_pmd, map_hva, &ptl);

	/* a page was faulted in */
	if (unlikely(pte_present(*ptep))) {
		atomic_inc(&stat_refault);
		result = -EAGAIN;
		goto out_unlock;
	}

	/* create new PTE based on requested page */
	pte = mk_pte(req_page, map_vma->vm_page_prot);
	if (map_vma->vm_flags & VM_WRITE)
		pte = pte_mkwrite(pte_mkdirty(pte));
	set_pte_at_notify(map_mm, map_hva, ptep, pte);

	inc_mm_counter(map_mm, MM_ANONPAGES);

out_unlock:
	pte_unmap_unlock(ptep, ptl);

	return result;
}

static void mm_remote_put_req(struct page *req_page,
			      struct anon_vma *req_anon_vma)
{
	if (req_anon_vma)
		put_anon_vma(req_anon_vma);

	if (req_page)
		put_page(req_page);
}

static int mm_remote_get_req(struct mm_struct *req_mm, unsigned long req_hva,
			     struct page **preq_page,
			     struct anon_vma **preq_anon_vma)
{
	struct page *req_page = NULL;
	struct anon_vma *req_anon_vma = NULL;
	long nrpages;
	int result = 0;

	/* for now we-re using both pointers */
	ASSERT(preq_page != NULL);
	ASSERT(preq_anon_vma != NULL);

	if (check_stable_address_space(req_mm)) {
		pr_err("address space of target not stable");
		return -EINVAL;
	}

	down_read(&req_mm->mmap_sem);

	/* get host page corresponding to requested address */
	nrpages = get_user_pages_remote(NULL, req_mm, req_hva, 1,
		FOLL_WRITE | FOLL_FORCE | FOLL_SPLIT | FOLL_MIGRATION,
		&req_page, NULL, NULL);
	if (unlikely(nrpages == 0)) {
		pr_err("no page for req_hva %016lx\n", req_hva);
		result = -ENOENT;
		goto out;
	} else if (IS_ERR_VALUE(nrpages)) {
		result = nrpages;
		if (result == -EBUSY)
			pr_debug("get_user_pages_remote() failed: %d\n", result);
		else
			pr_err("get_user_pages_remote() failed: %d\n", result);
		goto out;
	}

	/* limit introspection to anon memory (this also excludes zero-page) */
	if (!PageAnon(req_page)) {
		result = -EINVAL;
		pr_err("page at req_hva %016lx not anon\n", req_hva);
		goto out;
	}

	/* make sure the application doesn't want remote-double-mapping */
	if (PageRemote(req_page)) {
		result = -EALREADY;
		pr_debug("page at req_hva %016lx already mapped\n", req_hva);
		goto out;
	}

	/* take & lock this anon vma */
	req_anon_vma = page_get_anon_vma(req_page);
	if (unlikely(req_anon_vma == NULL)) {
		result = -EINVAL;
		pr_err("no anon vma for req_hva %016lx\n", req_hva);
		goto out;
	}

	/* output these values only if successful */
	*preq_page = req_page;
	*preq_anon_vma = req_anon_vma;

out:
	up_read(&req_mm->mmap_sem);

	if (result)
		mm_remote_put_req(req_page, req_anon_vma);

	return result;
}

static int mm_remote_remap(struct mm_struct *map_mm, unsigned long map_hva,
			   struct page *req_page, struct anon_vma *req_anon_vma,
			   struct page_db *pdb)
{
	struct vm_area_struct *map_vma;
	pmd_t *map_pmd;
	struct page *map_page = NULL;
	int result = 0;

	/* this allows faulting to happen */
	down_read(&map_mm->mmap_sem);

	/* find VMA containing address */
	map_vma = find_vma(map_mm, map_hva);
	if (unlikely(map_vma == NULL)) {
		result = -ENOENT;
		pr_err("no local VMA found for remapping\n");
		goto out_unlock;
	}

	if (unlikely(!vma_is_anonymous(map_vma))) {
		result = -EINVAL;
		pr_err("local VMA is not anonymous\n");
		goto out_unlock;
	}
	ASSERT(map_vma->anon_vma != NULL);

retry:
	/*
	 * get reference to local page corresponding to target address;
	 * the result may be NULL in case of swap entry or mapping not present
	 */
	map_page = follow_page(map_vma, map_hva,
			       FOLL_SPLIT | FOLL_MIGRATION | FOLL_GET);
	if (IS_ERR_VALUE(map_page)) {
		result = PTR_ERR(map_page);
		pr_debug("%s: follow_page() failed: %d\n", __func__, result);
		goto out_unlock;
	}

	/* in case of THP, the huge page must be split before the PMD exists */
	map_pmd = mm_find_pmd(map_mm, map_hva);
	if (unlikely(!map_pmd)) {
		/* follow_page(... | FOLL_GET) */
		if (map_page != NULL)
			put_page(map_page);
		result = -EFAULT;
		pr_err("local PMD not found");
		goto out_unlock;
	}

	/* unmap map_page from current page tables */
	if (map_page != NULL)
		lock_page(map_page);

	/* the only possible error is -EAGAIN when map_page == NULL */
	result = mm_remote_invalidate_pte(map_vma, map_hva, map_pmd, map_page);
	if (IS_ERR_VALUE((long)result))
		goto retry;

	if (map_page != NULL)
		unlock_page(map_page);

	/* we're done with this page */
	if (map_page != NULL) {
		/* reference acquired in follow_page(... | FOLL_GET) */
		put_page(map_page);
		free_page_and_swap_cache(map_page);
	}

	/* map req_page at the same address - page is already PageRemote() */
	lock_page(req_page);

	/* the only possible error is -EAGAIN when PTE != pte_none() */
	result = mm_remote_install_pte(map_vma, map_hva, map_pmd, req_page);
	if (IS_ERR_VALUE((long)result)) {
		unlock_page(req_page);
		goto retry;
	}

	/* increment its reference to outlive OOM */
	get_anon_vma(map_vma->anon_vma);
	pdb->map_anon_vma = map_vma->anon_vma;

	/* will only increment the mapcount of this page */
	page_add_anon_rmap(req_page, map_vma, map_hva, false);

	unlock_page(req_page);

	/* local accounting */
	atomic_inc(&map_count);

out_unlock:
	up_read(&map_mm->mmap_sem);

	return result;
}

static int mm_remote_promote_page(struct page *req_page,
				  struct anon_vma *req_anon_vma,
				  struct page_db *pdb)
{
	int result = 0;

	lock_page(req_page);

	/*
	 * maybe some other thread mapping the same page in another file
	 * reached here before us
	 */
	if (PageRemote(req_page)) {
		result = -EALREADY;
		goto out_unlock;
	}

	/* make this page remote, mapped only under the target */
	pdb->req_anon_vma = req_anon_vma;
	req_page->mapping = PageMapping(pdb);

	mm_remote_page_unevictable(req_page);
	atomic_inc(&rpg_count);

out_unlock:
	unlock_page(req_page);

	return result;
}

static void mm_remote_revert_promote(struct page *req_page)
{
	struct page_db *pdb;

	/* the page must have been made remote by this thread */
	ASSERT(PageRemote(req_page));

	lock_page(req_page);

	pdb = RemoteMapping(req_page);

	/* revert the mapping back to anon page mapped under target */
	req_page->mapping = (void *)pdb->req_anon_vma + PAGE_MAPPING_ANON;
	pdb->req_anon_vma = NULL;

	mm_remote_page_evictable(req_page);
	BUG_ON(atomic_add_negative(-1, &rpg_count));

	unlock_page(req_page);
}

static int mm_remote_do_map(struct mm_struct *req_mm, unsigned long req_hva,
			    struct mm_struct *map_mm, unsigned long map_hva,
			    struct page_db *pdb)
{
	struct page *req_page;
	struct anon_vma *req_anon_vma;
	int result;

	result = mm_remote_get_req(req_mm, req_hva, &req_page, &req_anon_vma);
	if (IS_ERR_VALUE((long)result))
		return result;

	result = mm_remote_promote_page(req_page, req_anon_vma, pdb);
	if (IS_ERR_VALUE((long)result))
		goto out_put;

	result = mm_remote_remap(map_mm, map_hva, req_page, req_anon_vma, pdb);
	if (IS_ERR_VALUE((long)result))
		goto out_revert;

	return 0;

out_revert:
	mm_remote_revert_promote(req_page);
out_put:
	mm_remote_put_req(req_page, req_anon_vma);

	return result;
}

static int mm_remote_map_file(struct file_db *fdb, struct mm_struct *req_mm,
			      unsigned long req_hva, unsigned long map_hva)
{
	struct mm_struct *map_mm = current->mm;
	struct page_db *pdb;
	int result = 0;

	/* tries to add the entry in the tree */
	pdb = page_db_reserve(fdb, req_mm, req_hva, map_hva);
	if (IS_ERR_VALUE(pdb))
		return PTR_ERR(pdb);

	/* do the actual memory mapping */
	result = mm_remote_do_map(req_mm, req_hva, map_mm, map_hva, pdb);
	if (IS_ERR_VALUE((long)result))
		goto out_pdb;

	/* add mapping to target database */
	result = page_db_add_target(pdb, req_mm, map_mm);
	if (IS_ERR_VALUE((long)result)) {
		mm_remote_do_unmap(map_mm, map_hva);
		goto out_pdb;
	}

	/* marks as mapped & drops reference */
	page_db_got_mapped(pdb);

	return 0;

out_pdb:
	/* removes the entry from the tree & drops reference */
	page_db_unreserve(fdb, pdb);

	return result;
}

int mm_remote_map(struct mm_struct *req_mm,
		  unsigned long req_hva, unsigned long map_hva)
{
	struct mm_struct *map_mm = current->mm;
	struct client_db *cdb;
	struct file_db *fdb;
	int result = 0;

	pr_debug("%s: req_mm %016lx, req_hva %016lx, map_hva %016lx\n",
		__func__, (unsigned long)req_mm, req_hva, map_hva);

	cdb = client_db_lookup_or_add(map_mm);
	if (IS_ERR_OR_NULL(cdb))
		return (cdb == NULL) ? -ENOMEM : PTR_ERR(cdb);

	fdb = client_db_pseudo_file(cdb);
	if (fdb == NULL) {
		result = -ENOMEM;
		goto out_cdb;
	}

	/* try to pin the target MM so it won't go away */
	if (!mmget_not_zero(req_mm)) {
		result = -EINVAL;
		goto out_cdb;
	}

	result = mm_remote_map_file(fdb, req_mm, req_hva, map_hva);
	mmput(req_mm);

out_cdb:
	client_db_put(cdb);

	return result;
}
EXPORT_SYMBOL_GPL(mm_remote_map);

static int mm_remote_do_unmap(struct mm_struct *map_mm, unsigned long map_hva)
{
	struct vm_area_struct *map_vma;
	pmd_t *map_pmd;
	struct page *req_page = NULL;
	struct anon_vma *req_anon_vma = NULL;
	struct page_db *pdb;
	int result = 0;

	/* this allows faulting to happen */
	down_read(&map_mm->mmap_sem);

	/* find destination VMA for mapping */
	map_vma = find_vma(map_mm, map_hva);
	if (unlikely(map_vma == NULL)) {
		result = -ENOENT;
		pr_err("no local VMA found for unmapping\n");
		goto out;
	}

	map_pmd = mm_find_pmd(map_mm, map_hva);
	if (unlikely(!map_pmd)) {
		result = -EFAULT;
		pr_err("local PMD not found");
		goto out;
	}

	/* get page mapped to destination address - we know it is there */
	req_page = follow_page(map_vma, map_hva, FOLL_GET | FOLL_MIGRATION);
	if (IS_ERR_VALUE(req_page)) {
		result = PTR_ERR(req_page);
		req_page = NULL;
		pr_err("follow_page() failed: %d\n", result);
		goto out;
	} else if (unlikely(req_page == NULL)) {
		result = -ENOENT;
		pr_err("follow_page() returned no page\n");
		goto out;
	}

	ASSERT(PageRemote(req_page));
	pdb = RemoteMapping(req_page);

	lock_page(req_page);

	/* also calls page_remove_rmap() */
	mm_remote_invalidate_pte(map_vma, map_hva, map_pmd, req_page);

	req_anon_vma = pdb->req_anon_vma;
	pdb->req_anon_vma = NULL;

	/* restore original rmap */
	req_page->mapping = (void *)req_anon_vma + PAGE_MAPPING_ANON;
	mm_remote_page_evictable(req_page);
	BUG_ON(atomic_add_negative(-1, &rpg_count));

	/* refcount was increased in mm_remote_remap() */
	put_anon_vma(pdb->map_anon_vma);
	pdb->map_anon_vma = NULL;

	unlock_page(req_page);

	/* follow_page(..., FOLL_GET...) */
	put_page(req_page);

	BUG_ON(atomic_add_negative(-1, &map_count));

	/* reference count was inc during mm_remote_get_req() */
	mm_remote_put_req(req_page, req_anon_vma);

out:
	up_read(&map_mm->mmap_sem);

	return result;
}

/*
 * In case the client's memory is reaped by the OOM killer, the remote pages'
 * reference count + mapcount is dropped and they belong just to the target.
 */
static int mm_remote_do_unmap_target(struct page_db *pdb)
{
	struct mm_struct *req_mm = pdb->target;
	struct vm_area_struct *req_vma;
	struct page *req_page = NULL;
	struct anon_vma *req_anon_vma = NULL;
	int result = 0;

	down_read(&req_mm->mmap_sem);

	req_vma = find_vma(req_mm, pdb->req_hva);
	if (unlikely(req_vma == NULL)) {
		result = -ENOENT;
		pr_err("no source VMA found for unmapping\n");
		goto out;
	}

	/* page is unevictable - should be mapped */
	req_page = follow_page(req_vma, pdb->req_hva, FOLL_GET | FOLL_MIGRATION);
	if (IS_ERR_VALUE(req_page)) {
		result = PTR_ERR(req_page);
		req_page = NULL;
		pr_err("follow_page() failed: %d\n", result);
		goto out;
	} else if (unlikely(req_page == NULL)) {
		result = -ENOENT;
		pr_err("follow_page() returned no page\n");
		goto out;
	}

	ASSERT(PageRemote(req_page));
	ASSERT(pdb == RemoteMapping(req_page));

	/*
	 * page_remove_rmap() must have been called when the page was unmapped
	 * from the client, now we must have a higher refcount from
	 * follow_page(...FOLL_GET...)
	 */

	lock_page(req_page);

	req_anon_vma = pdb->req_anon_vma;
	pdb->req_anon_vma = NULL;

	/* restore original rmap */
	req_page->mapping = (void *)req_anon_vma + PAGE_MAPPING_ANON;
	mm_remote_page_evictable(req_page);
	BUG_ON(atomic_add_negative(-1, &rpg_count));

	/* refcount was increased in mm_remote_remap() */
	put_anon_vma(pdb->map_anon_vma);
	pdb->map_anon_vma = NULL;

	unlock_page(req_page);

	BUG_ON(atomic_add_negative(-1, &map_count));

	/* client doesn't map this page anymore, a single refcount to drop */
	mm_remote_put_req(req_page, req_anon_vma);

out:
	up_read(&req_mm->mmap_sem);

	return result;
}

static int mm_remote_unmap_file(struct file_db *fdb, unsigned long map_hva)
{
	struct mm_struct *map_mm = current->mm;
	struct mm_struct *req_mm;
	struct page_db *pdb;
	int result;

	/* take exclusive access to this pdb */
	pdb = page_db_begin_unmap(fdb, map_hva);
	if (IS_ERR_OR_NULL(pdb))
		return (pdb == NULL) ? -ENOENT : PTR_ERR(pdb);

	/* test if other thread unmapped this address before us */
	if (!test_bit(MAPPED_BIT, (unsigned long *)&pdb->flags)) {
		result = -EALREADY;
		goto just_release;
	}

	/* also disconnect from target - can fail if target exited */
	result = page_db_remove_target(pdb);
	if (IS_ERR_VALUE((long)result))
		pr_debug("%s: page_db_remove_target() failed: %d\n",
			__func__, result);

	/* the unmapping is done on local mm only */
	result = mm_remote_do_unmap(map_mm, map_hva);
	if (IS_ERR_VALUE((long)result)) {
		pr_debug("%s: mm_remote_do_unmap() failed: %d, trying target\n",
			__func__, result);

		req_mm = pdb->target;
		if (mmget_not_zero(req_mm)) {
			result = mm_remote_do_unmap_target(pdb);

			mmput(req_mm);
		}
	}

just_release:
	/* marks as unmapped & drops reference */
	page_db_end_unmap(fdb, pdb);

	return result;
}

int mm_remote_unmap(unsigned long map_hva)
{
	struct mm_struct *map_mm = current->mm;
	struct client_db *cdb;
	struct file_db *fdb;
	int result;

	pr_debug("%s: map_hva %016lx\n", __func__, map_hva);

	cdb = client_db_lookup_or_add(map_mm);
	if (IS_ERR_OR_NULL(cdb))
		return (cdb == NULL) ? -ENOMEM : PTR_ERR(cdb);

	fdb = client_db_pseudo_file(cdb);
	if (fdb == NULL) {
		result = -ENOMEM;
		goto out_cdb;
	}

	result = mm_remote_unmap_file(fdb, map_hva);

out_cdb:
	client_db_put(cdb);

	return result;
}
EXPORT_SYMBOL_GPL(mm_remote_unmap);

/* called on behalf of the client */
void mm_remote_reset(void)
{
	struct mm_struct *map_mm = current->mm;
	struct client_db *cdb;

	pr_debug("%s\n", __func__);

	/* also gets reference to entry */
	cdb = client_db_lookup(map_mm);
	if (cdb == NULL)
		return;

	/* no locking here, we have exclusive access */
	mm_remote_db_client_release(cdb);

	client_db_put(cdb);
}
EXPORT_SYMBOL_GPL(mm_remote_reset);

static int remmap_dev_open(struct inode *inodep, struct file *filp)
{
	struct file_db *fdb;
	struct client_db *cdb;
	int result = 0;

	fdb = file_db_alloc();
	if (fdb == NULL)
		return -ENOMEM;

	/* we need the mm to exist at file closing time */
	mmget(current->mm);

	cdb = client_db_lookup_or_add(current->mm);
	if (IS_ERR_OR_NULL(cdb)) {
		result = (cdb == NULL) ? -ENOMEM : PTR_ERR(cdb);
		goto out_err;
	}

	fdb->cdb = cdb;
	filp->private_data = fdb;

	/* by pinning the mm we also make sure the cdb does not get released */
	client_db_put(cdb);

	return 0;

out_err:
	mmput(current->mm);
	file_db_free(fdb);

	return result;
}

static long remmap_dev_ioctl(struct file *filp, unsigned int ioctl,
			     unsigned long arg)
{
	void __user *argp = (void __user *) arg;
	struct file_db *fdb = filp->private_data;
	struct client_db *cdb = fdb->cdb;
	long result = 0;

	if (current->mm != cdb->mm) {
		pr_err("ioctl request by different process\n");
		return -EINVAL;
	}

	switch (ioctl) {
	case REMOTE_MAP: {
		struct remote_map_request req;
		struct task_struct *req_task;
		struct mm_struct *req_mm;

		result = -EFAULT;
		if (copy_from_user(&req, argp, sizeof(req)))
			break;

		result = -EINVAL;
		if (!access_ok(req.map_hva, PAGE_SIZE))
			break;
		if (req.req_hva & ~PAGE_MASK)
			break;
		if (req.map_hva & ~PAGE_MASK)
			break;

		result = -ESRCH;
		req_task = find_get_task_by_vpid(req.req_pid);
		if (req_task == NULL)
			break;

		result = -EINVAL;
		req_mm = get_task_mm(req_task);
		put_task_struct(req_task);
		if (req_mm == NULL)
			break;

		result = mm_remote_map_file(fdb, req_mm, req.req_hva, req.map_hva);
		mmput(req_mm);

		break;
	}

	case REMOTE_UNMAP: {
		unsigned long map_hva = (unsigned long) arg;

		result = -EINVAL;
		if (!access_ok(map_hva, PAGE_SIZE))
			break;
		if (map_hva & ~PAGE_MASK)
			break;

		result = mm_remote_unmap_file(fdb, map_hva);

		break;
	}

	default:
		pr_err("ioctl %d not implemented\n", ioctl);
		result = -ENOTTY;
	}

	return result;
}

static int remmap_dev_release(struct inode *inodep, struct file *filp)
{
	struct file_db *fdb = filp->private_data;
	struct client_db *cdb = fdb->cdb;
	struct mm_struct *mm = cdb->mm;

	mm_remote_db_file_release(fdb);
	file_db_free(fdb);

	/*
	 * we may have reached here by killing the client process,
	 * current->mm is not accessible anymore
	 */
	mmput(mm);

	return 0;
}

static const struct file_operations remmap_ops = {
	.open = remmap_dev_open,
	.unlocked_ioctl = remmap_dev_ioctl,
	.compat_ioctl = remmap_dev_ioctl,
	.release = remmap_dev_release,
};

static struct miscdevice remmap_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "remote-map",
	.fops = &remmap_ops,
};

builtin_misc_device(remmap_dev);

#ifdef CONFIG_DEBUG_FS
static void __init mm_remote_debugfs_init(void)
{
	mm_remote_debugfs_dir = debugfs_create_dir("remote_mapping", NULL);
	if (mm_remote_debugfs_dir == NULL)
		return;

	debugfs_create_atomic_t("map_count", 0444, mm_remote_debugfs_dir,
				&map_count);
	debugfs_create_atomic_t("pdb_count", 0444, mm_remote_debugfs_dir,
				&pdb_count);
	debugfs_create_atomic_t("rpg_count", 0444, mm_remote_debugfs_dir,
				&rpg_count);

	debugfs_create_atomic_t("stat_empty_pte", 0444, mm_remote_debugfs_dir,
				&stat_empty_pte);
	debugfs_create_atomic_t("stat_mapped_pte", 0444, mm_remote_debugfs_dir,
				&stat_mapped_pte);
	debugfs_create_atomic_t("stat_swap_pte", 0444, mm_remote_debugfs_dir,
				&stat_swap_pte);
	debugfs_create_atomic_t("stat_refault", 0444, mm_remote_debugfs_dir,
				&stat_refault);
}
#else /* CONFIG_DEBUG_FS */
static void __init mm_remote_debugfs_init(void)
{
}
#endif /* CONFIG_DEBUG_FS */

static int __init mm_remote_init(void)
{
	pdb_cache = KMEM_CACHE(page_db, SLAB_PANIC | SLAB_ACCOUNT);
	if (!pdb_cache)
		return -ENOMEM;

	mm_remote_debugfs_init();

	return 0;
}
device_initcall(mm_remote_init);
