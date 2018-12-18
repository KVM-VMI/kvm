// SPDX-License-Identifier: GPL-2.0
/*
 * Remote memory mapping.
 *
 * Copyright (C) 2017-2018 Bitdefender S.R.L.
 *
 * Author:
 *   Mircea Cirjaliu <mcirjaliu@bitdefender.com>
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/rmap.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/mm.h>
#include <linux/huge_mm.h>
#include <linux/mmu_notifier.h>
#include <linux/sched/mm.h>
#include <linux/interval_tree_generic.h>
#include <linux/hashtable.h>
#include <linux/refcount.h>
#include <linux/debugfs.h>
#include "internal.h"

#define ASSERT(exp) BUG_ON(!(exp))

#define TAKEN_BIT 0
#define TDB_HASH_BITS 4
#define IDB_HASH_BITS 2

struct page_db {
	/* Target for this mapping */
	struct mm_struct *target;

	/* HVAs of target & introspector */
	unsigned long req_hva;
	unsigned long map_hva;

	/* Target-side link (interval tree) */
	union {
		struct {
			struct rb_node target_rb;
			unsigned long rb_subtree_last;
		};
		struct list_head temp;
	};

	/* Introspector-side link (RB tree) */
	struct rb_node intro_rb;

	unsigned long flags;
};

struct target_db {
	struct mm_struct *mm;		/* mm of this struct */
	struct hlist_node db_link;	/* database link */

	struct mmu_notifier mn;		/* for notifications from mm */
	struct rcu_head	rcu;		/* for delayed freeing */
	refcount_t refcnt;

	spinlock_t lock;		/* lock for the following */
	struct mm_struct *introspector;	/* introspector for this target */
	struct rb_root_cached rb_root;	/* mapped HVA from this target */
};

struct intro_db {
	struct mm_struct *mm;		/* mm of this struct */
	struct hlist_node db_link;	/* database link */

	struct mmu_notifier mn;		/* for notifications from mm */
	struct rcu_head	rcu;		/* for delayed freeing */
	refcount_t refcnt;

	spinlock_t lock;		/* lock for the following */
	struct rb_root rb_root;		/* for local mappings */
};

/* forward declarations */
static int mm_remote_unmap_action(struct mm_struct *map_mm,
				  unsigned long map_hva);

static void mm_remote_db_target_release(struct target_db *tdb);
static void mm_remote_db_intro_release(struct intro_db *idb);

static void tdb_release(struct mmu_notifier *mn, struct mm_struct *mm);
static void idb_release(struct mmu_notifier *mn, struct mm_struct *mm);

static const struct mmu_notifier_ops tdb_notifier_ops = {
	.release = tdb_release,
};

static const struct mmu_notifier_ops idb_notifier_ops = {
	.release = idb_release,
};

static DEFINE_HASHTABLE(tdb_hash, TDB_HASH_BITS);
static DEFINE_SPINLOCK(tdb_lock);

static DEFINE_HASHTABLE(idb_hash, IDB_HASH_BITS);
static DEFINE_SPINLOCK(idb_lock);

static struct kmem_cache *pdb_cache;
static atomic_t pdb_count = ATOMIC_INIT(0);
static atomic_t map_count = ATOMIC_INIT(0);

static struct dentry *mm_remote_debugfs_dir;

static void target_db_init(struct target_db *tdb, struct mm_struct *mm)
{
	tdb->mm = mm;
	tdb->mn.ops = &tdb_notifier_ops;
	refcount_set(&tdb->refcnt, 1);

	tdb->introspector = NULL;
	tdb->rb_root = RB_ROOT_CACHED;
	spin_lock_init(&tdb->lock);
}

static inline unsigned long page_db_start(const struct page_db *pdb)
{
	return pdb->req_hva;
}

static inline unsigned long page_db_last(const struct page_db *pdb)
{
	return pdb->req_hva + PAGE_SIZE;
}

INTERVAL_TREE_DEFINE(struct page_db, target_rb, unsigned long,
	rb_subtree_last, page_db_start, page_db_last,
	static inline, __page_db_interval_tree)

static void target_db_insert(struct target_db *tdb, struct page_db *pdb)
{
	__page_db_interval_tree_insert(pdb, &tdb->rb_root);
}

static bool target_db_empty(const struct target_db *tdb)
{
	return RB_EMPTY_ROOT(&tdb->rb_root.rb_root);
}

static bool target_db_remove(struct target_db *tdb, struct page_db *pdb)
{
	bool result = false;

	if (!target_db_empty(tdb)) {
		__page_db_interval_tree_remove(pdb, &tdb->rb_root);
		result = true;
	}

	RB_CLEAR_NODE(&pdb->target_rb);
	pdb->rb_subtree_last = 0;

	return result;
}

#define target_db_foreach(pdb, root, start, last)	\
	for (pdb = __page_db_interval_tree_iter_first(root, start, last);\
	     pdb; pdb = __page_db_interval_tree_iter_next(pdb, start, last))

static void target_db_get(struct target_db *tdb)
{
	refcount_inc(&tdb->refcnt);
}

static void target_db_free_delayed(struct rcu_head *rcu)
{
	struct target_db *tdb = container_of(rcu, struct target_db, rcu);

	pr_debug("%s: for mm %016lx\n", __func__, (unsigned long)tdb->mm);

	kfree(tdb);
}

static void target_db_put(struct target_db *tdb)
{
	if (refcount_dec_and_test(&tdb->refcnt)) {
		pr_debug("%s: for MM %016lx\n", __func__,
			(unsigned long)tdb->mm);

		mm_remote_db_target_release(tdb);

		ASSERT(target_db_empty(tdb));

		mmu_notifier_call_srcu(&tdb->rcu, target_db_free_delayed);
	}
}

static struct target_db *target_db_lookup(const struct mm_struct *mm)
{
	struct target_db *tdb;

	spin_lock(&tdb_lock);
	hash_for_each_possible(tdb_hash, tdb, db_link, (unsigned long)mm)
		if (tdb->mm == mm) {
			target_db_get(tdb);
			spin_unlock(&tdb_lock);

			return tdb;
		}
	spin_unlock(&tdb_lock);

	return NULL;
}

static void target_db_extract(struct target_db *tdb)
{
	spin_lock(&tdb_lock);
	hash_del(&tdb->db_link);
	spin_unlock(&tdb_lock);
}

static struct target_db *target_db_lookup_or_add(struct mm_struct *mm)
{
	struct target_db *tdb;
	int result;

	spin_lock(&tdb_lock);

	/* lookup in hash */
	hash_for_each_possible(tdb_hash, tdb, db_link, (unsigned long)mm)
		if (tdb->mm == mm) {
			target_db_get(tdb);
			spin_unlock(&tdb_lock);

			return tdb;
		}

	/* no tdb found, alloc one */
	tdb = kzalloc(sizeof(*tdb), GFP_ATOMIC);
	if (tdb == NULL) {
		spin_unlock(&tdb_lock);
		return ERR_PTR(-ENOMEM);
	}

	/* init & add to hash */
	target_db_init(tdb, mm);
	hash_add(tdb_hash, &tdb->db_link, (unsigned long)mm);

	spin_unlock(&tdb_lock);

	/*
	 * register a mmu notifier when adding this entry to the list - at this
	 * point other threads may already have hold of this tdb
	 */
	result = mmu_notifier_register(&tdb->mn, mm);
	if (IS_ERR_VALUE((long) result)) {
		target_db_extract(tdb);
		target_db_put(tdb);
		return ERR_PTR((long) result);
	}

	pr_debug("%s: new entry for mm %016lx\n",
		__func__, (unsigned long)tdb->mm);

	/* return this entry to user with incremented reference count */
	target_db_get(tdb);

	return tdb;
}

static void intro_db_init(struct intro_db *idb, struct mm_struct *mm)
{
	idb->mm = mm;
	idb->mn.ops = &idb_notifier_ops;
	refcount_set(&idb->refcnt, 1);

	idb->rb_root = RB_ROOT;
	spin_lock_init(&idb->lock);
}

static void intro_db_insert(struct intro_db *idb, struct page_db *pdb)
{
	struct rb_root *root = &idb->rb_root;
	struct rb_node **new = &root->rb_node;
	struct rb_node *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct page_db *this = rb_entry(*new, struct page_db, intro_rb);

		parent = *new;
		if (pdb->map_hva < this->map_hva)
			new = &((*new)->rb_left);
		else if (pdb->map_hva > this->map_hva)
			new = &((*new)->rb_right);
		else {
			ASSERT(pdb->map_hva != this->map_hva);
			return;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&pdb->intro_rb, parent, new);
	rb_insert_color(&pdb->intro_rb, root);
}

static struct page_db *intro_db_search(struct intro_db *idb,
				       unsigned long map_hva)
{
	struct rb_root *root = &idb->rb_root;
	struct rb_node *node = root->rb_node;

	while (node) {
		struct page_db *pdb = rb_entry(node, struct page_db, intro_rb);

		if (map_hva < pdb->map_hva)
			node = node->rb_left;
		else if (map_hva > pdb->map_hva)
			node = node->rb_right;
		else
			return pdb;
	}

	return NULL;
}

static bool intro_db_empty(const struct intro_db *idb)
{
	return RB_EMPTY_ROOT(&idb->rb_root);
}

static bool intro_db_remove(struct intro_db *idb, struct page_db *pdb)
{
	bool result = false;

	if (!intro_db_empty(idb)) {
		rb_erase(&pdb->intro_rb, &idb->rb_root);
		result = true;
	}

	RB_CLEAR_NODE(&pdb->intro_rb);

	return result;
}

static void intro_db_get(struct intro_db *idb)
{
	refcount_inc(&idb->refcnt);
}

static void intro_db_free_delayed(struct rcu_head *rcu)
{
	struct intro_db *idb = container_of(rcu, struct intro_db, rcu);

	pr_debug("%s: mm %016lx\n", __func__, (unsigned long)idb->mm);

	kfree(idb);
}

static void intro_db_put(struct intro_db *idb)
{
	if (refcount_dec_and_test(&idb->refcnt)) {
		pr_debug("%s: mm %016lx\n", __func__, (unsigned long)idb->mm);

		mm_remote_db_intro_release(idb);

		ASSERT(intro_db_empty(idb));

		mmu_notifier_call_srcu(&idb->rcu, intro_db_free_delayed);
	}
}

static struct intro_db *intro_db_lookup(const struct mm_struct *mm)
{
	struct intro_db *idb;

	spin_lock(&idb_lock);
	hash_for_each_possible(idb_hash, idb, db_link, (unsigned long)mm)
		if (idb->mm == mm) {
			intro_db_get(idb);
			spin_unlock(&idb_lock);

			return idb;
		}
	spin_unlock(&idb_lock);

	return NULL;
}

static void intro_db_extract(struct intro_db *idb)
{
	spin_lock(&idb_lock);
	hash_del(&idb->db_link);
	spin_unlock(&idb_lock);
}

static struct intro_db *intro_db_lookup_or_add(struct mm_struct *mm)
{
	struct intro_db *idb;
	int result;

	spin_lock(&idb_lock);

	/* lookup in hash */
	hash_for_each_possible(idb_hash, idb, db_link, (unsigned long)mm)
		if (idb->mm == mm) {
			intro_db_get(idb);
			spin_unlock(&idb_lock);

			return idb;
		}

	/* no mdb found, alloc one */
	idb = kzalloc(sizeof(*idb), GFP_ATOMIC);
	if (idb == NULL) {
		spin_unlock(&idb_lock);
		return ERR_PTR(-ENOMEM);
	}

	/* init & add to hash */
	intro_db_init(idb, mm);
	hash_add(idb_hash, &idb->db_link, (unsigned long)mm);

	spin_unlock(&idb_lock);

	/*
	 * register a mmu notifier when adding this entry to the list - at this
	 * point other threads may already have hold of this idb
	 */
	result = mmu_notifier_register(&idb->mn, mm);
	if (IS_ERR_VALUE((long)result)) {
		intro_db_extract(idb);
		intro_db_put(idb);
		return ERR_PTR((long)result);
	}

	pr_debug("%s: new entry for mm %016lx\n",
		__func__, (unsigned long)idb->mm);

	/* return this entry to user with incremented reference count */
	intro_db_get(idb);

	return idb;
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

/*
 * According to the new semantics, we first reserve a mapping entry in the
 * introspector and we mark it as taken. Any other thread trying to insert
 * the same mapping (identified by map_hva) will return with -EALREADY. The
 * entry will be marked as taken as long as the owning thread works on it.
 * The taken bit serves to synchronize with any unmapper thread trying to
 * extract this entry from the database at the same time. Clearing this bit
 * is not ordered relative to other instructions, so it may be cleared by
 * the owner but read as set by an unmapper thread in the introspector
 * critical region.
 */
static int
page_db_reserve(struct mm_struct *introspector, unsigned long map_hva,
		struct mm_struct *target, unsigned long req_hva,
		struct page_db **ppdb)
{
	struct intro_db *idb;
	struct page_db *pdb;
	int result = 0;

	/*
	 * returns a valid pointer or an error value, never NULL
	 * also gets reference to entry
	 */
	idb = intro_db_lookup_or_add(introspector);
	if (IS_ERR_VALUE(idb))
		return PTR_ERR(idb);

	/*
	 * alloc mapping entry outside the introspector critical region - most
	 * likely the entry (identified by map_hva) isn't already reserved in
	 * the tree and we won't need to throw the allocation away
	 */
	pdb = page_db_alloc();
	if (unlikely(pdb == NULL)) {
		result = -ENOMEM;
		goto out;
	}

	/* fill pdb */
	pdb->target = target;
	pdb->req_hva = req_hva;
	pdb->map_hva = map_hva;

	/* insert mapping entry into the introspector if not already there */
	spin_lock(&idb->lock);

	if (unlikely(intro_db_search(idb, map_hva))) {
		page_db_free(pdb);
		result = -EALREADY;
	} else {
		intro_db_insert(idb, pdb);
		/*
		 * after the introspector critical region ends, this flag will
		 * be read as set because of the implicit memory barrier of the
		 * unlock op
		 */
		__set_bit(TAKEN_BIT, &pdb->flags);
	}

	spin_unlock(&idb->lock);

	/* output this value */
	if (result == 0)
		*ppdb = pdb;

out:
	/*
	 * do not free MDBs for the introspector/target, just unpin them;
	 * they will get freed by the mmu_notifier->release() callbacks
	 */
	intro_db_put(idb);

	return result;
}

/*
 * This function should be called at the beginning of the unmap function, it
 * will take ownership of the entry if possible, then the entry can be removed
 * from the target database. After removal, the entry can be unreserved.
 */
static int
page_db_acquire(struct mm_struct *introspector, unsigned long map_hva,
		struct page_db **ppdb)
{
	struct intro_db *idb;
	struct page_db *pdb;
	int result = 0;

	/* also gets reference to entry */
	idb = intro_db_lookup(introspector);
	if (idb == NULL)
		return -EINVAL;

	spin_lock(&idb->lock);

	pdb = intro_db_search(idb, map_hva);
	if (pdb == NULL) {
		result = -ENOENT;
	} else if (__test_and_set_bit(TAKEN_BIT, &pdb->flags)) {
		/*
		 * other thread owns this entry and may map or unmap it (in
		 * which case the entry will be gone entirely), the only action
		 * suitable is to retry access and hope the entry is there
		 */
		result = -EAGAIN;
	}

	spin_unlock(&idb->lock);

	/* output this value */
	if (result == 0)
		*ppdb = pdb;

	/*
	 * do not free MDBs for the introspector/target, just unpin them;
	 * they will get freed by the mmu_notifier->release() callbacks
	 */
	intro_db_put(idb);

	return result;
}

static void
page_db_release(struct page_db *pdb)
{
	__clear_bit(TAKEN_BIT, &pdb->flags);
}

/*
 * Reverse of page_db_reserve(), must be called by the same introspector thread
 * that has acquired the mapping entry by page_db_reserve()/page_db_acquire().
 */
static int
page_db_unreserve(struct mm_struct *introspector, struct page_db *pdb)
{
	struct intro_db *idb;
	bool removed;
	int result = 0;

	/* also gets reference to entry */
	idb = intro_db_lookup(introspector);
	if (idb == NULL)
		return -EINVAL;

	spin_lock(&idb->lock);
	removed = intro_db_remove(idb, pdb);
	spin_unlock(&idb->lock);

	page_db_free(pdb);

	if (!removed)
		pr_debug("%s: entry for map_hva %016lx already freed.\n",
			__func__, pdb->map_hva);

	/*
	 * do not free MDBs for the introspector/target, just unpin them;
	 * they will get freed by the mmu_notifier->release() callbacks
	 */
	intro_db_put(idb);

	return result;
}

static int
page_db_add_target(struct page_db *pdb, struct mm_struct *target,
		   struct mm_struct *introspector)
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
	if (tdb->introspector != NULL && tdb->introspector != introspector)
		result = -EINVAL;
	else {
		tdb->introspector = introspector;
		target_db_insert(tdb, pdb);
	}

	spin_unlock(&tdb->lock);

	/*
	 * do not free MDBs for the introspector/target, just unpin them;
	 * they will get freed by the mmu_notifier->release() callbacks
	 */
	target_db_put(tdb);

	return result;
}

static int
page_db_remove_target(struct page_db *pdb)
{
	struct target_db *tdb;
	int result = 0;
	bool removed;

	/* find target entry in the database */
	tdb = target_db_lookup(pdb->target);
	if (tdb == NULL)
		return -EINVAL;

	/* target-side locking */
	spin_lock(&tdb->lock);

	/* remove mapping from target */
	removed = target_db_remove(tdb, pdb);
	if (!removed)
		pr_debug("%s: mapping for req_hva %016lx of %016lx already freed\n",
			__func__, pdb->req_hva, (unsigned long)pdb->target);

	/* clear the introspector if no more mappings */
	if (target_db_empty(tdb)) {
		tdb->introspector = NULL;
		pr_debug("%s: all mappings gone for target mm %016lx\n",
			__func__, (unsigned long)pdb->target);
	}

	spin_unlock(&tdb->lock);

	/*
	 * do not free MDBs for the introspector/target, just unpin them;
	 * they will get freed by the mmu_notifier->release() callbacks
	 */
	target_db_put(tdb);

	return result;
}

/*
 * The target is referenced by a bunch of PDBs not reachable from introspector;
 * go there and break the target-side links (by removing the tree) while at the
 * same time clear the pointers from the PDBs to this target. In this way, the
 * current target will be reachable a single time while walking a tree of PDBs
 * extracted from the introspector.
 */
static void mm_remote_db_cleanup_target(struct target_db *tdb)
{
	struct page_db *pdb, *npdb;
	struct rb_root temp_rb;
	struct mm_struct *introspector;
	long result;

	/* target-side locking */
	spin_lock(&tdb->lock);

	/* if we ended up here the target must be introspected */
	ASSERT(tdb->introspector != NULL);
	introspector = tdb->introspector;
	tdb->introspector = NULL;

	/* take away the interval tree from the target */
	temp_rb.rb_node = tdb->rb_root.rb_root.rb_node;
	tdb->rb_root = RB_ROOT_CACHED;

	spin_unlock(&tdb->lock);

	/*
	 * walk the tree & clear links to target - this function is serialized
	 * with respect to the main loop in mm_remote_db_intro_release() so
	 * there will be no race on pdb->target
	 */
	rbtree_postorder_for_each_entry_safe(pdb, npdb, &temp_rb, target_rb) {
		/* clear links to target */
		pdb->target = NULL;
		pdb->rb_subtree_last = 0;
		RB_CLEAR_NODE(&pdb->target_rb);

		/* do the unmapping */
		result = mm_remote_unmap_action(introspector, pdb->map_hva);
		if (IS_ERR_VALUE(result))
			pr_debug("%s: failed unmapping map_hva %016lx!\n",
				__func__, pdb->map_hva);
	}
}

/*
 * The introspector is closing. This means the normal mapping/unmapping logic
 * does not work anymore.
 * This function will not race against mm_remote_db_target_release(), since the
 * introspector's MM is pinned during that call.
 */
static void mm_remote_db_intro_release(struct intro_db *idb)
{
	struct page_db *pdb, *npdb;
	struct target_db *tdb;
	struct rb_root temp_rb;

	/* introspector-side locking */
	spin_lock(&idb->lock);

	/* take away the internal tree */
	temp_rb.rb_node = idb->rb_root.rb_node;
	idb->rb_root = RB_ROOT;

	spin_unlock(&idb->lock);

	if (!RB_EMPTY_ROOT(&temp_rb))
		pr_debug("%s: introspector mm %016lx has some mappings\n",
			__func__, (unsigned long)idb->mm);

	/* iterate the tree over introspector entries */
	rbtree_postorder_for_each_entry_safe(pdb, npdb, &temp_rb, intro_rb) {
		/* see comments in function above */
		if (pdb->target == NULL)
			goto just_free;

		/* pin entry for target - maybe it has been released */
		tdb = target_db_lookup(pdb->target);
		if (tdb == NULL)
			goto just_free;

		/* see comments of this function */
		mm_remote_db_cleanup_target(tdb);

		/* unpin entry for target */
		target_db_put(tdb);

just_free:
		page_db_free(pdb);
	}
}

/*
 * The target MM is closing. This means the pages are unmapped by the default
 * kernel logic on the target side, but we must also clear the mappings on the
 * introspector side.
 * This function won't collide with the mapping function since we get here on
 * target MM teardown and the mapping function won't be able to get a reference
 * to the target MM.
 * Thin function may collide with the unmapping function that acquires mappings
 * in which case the acquired mappings are ignored.
 */
static void mm_remote_db_target_release(struct target_db *tdb)
{
	struct page_db *pdb, *npdb;
	struct intro_db *idb;
	struct mm_struct *introspector;
	struct rb_root temp_rb;
	LIST_HEAD(temp_list);
	long result;

	/* target-side locking */
	spin_lock(&tdb->lock);

	/* no introspector, nothing to do */
	if (tdb->introspector == NULL) {
		ASSERT(target_db_empty(tdb));
		spin_unlock(&tdb->lock);
		return;
	}

	/* extract introspector */
	introspector = tdb->introspector;
	tdb->introspector = NULL;

	/* take away the interval tree from the target */
	temp_rb.rb_node = tdb->rb_root.rb_root.rb_node;
	tdb->rb_root = RB_ROOT_CACHED;

	spin_unlock(&tdb->lock);

	/* pin the introspector mm so it won't go away */
	if (!mmget_not_zero(introspector))
		return;

	/*
	 * acquire the entry of the introspector - can be NULL if the
	 * introspector failed to register a MMU notifier
	 */
	idb = intro_db_lookup(introspector);
	if (idb == NULL)
		goto out_introspector;

	/* introspector-side locking */
	spin_lock(&idb->lock);

	rbtree_postorder_for_each_entry_safe(pdb, npdb, &temp_rb, target_rb) {
		/*
		 * this mapping entry happens to be taken (most likely) for
		 * unmapping individually, leave it alone
		 */
		if (__test_and_set_bit(TAKEN_BIT, &pdb->flags)) {
			pr_debug("%s: skip acquired mapping for map_hva %016lx\n",
				__func__, pdb->map_hva);
			continue;
		}

		/* add it to temp list for later processing */
		list_add(&pdb->temp, &temp_list);
	}

	spin_unlock(&idb->lock);

	/* unmap entries outside introspector lock */
	list_for_each_entry(pdb, &temp_list, temp) {
		pr_debug("%s: internal unmapping of map_hva %016lx\n",
			__func__, pdb->map_hva);

		/* do the unmapping */
		result = mm_remote_unmap_action(introspector, pdb->map_hva);
		if (IS_ERR_VALUE(result))
			pr_debug("%s: failed unmapping map_hva %016lx!\n",
				__func__, pdb->map_hva);
	}

	spin_lock(&idb->lock);

	/* loop over temp list & remove from introspector tree */
	list_for_each_entry_safe(pdb, npdb, &temp_list, temp) {
		/*
		 * unmap & free only if found in the introspector tree, it may
		 * have been already extracted & processed by another code path
		 */
		if (!intro_db_remove(idb, pdb))
			continue;

		page_db_free(pdb);
	}

	spin_unlock(&idb->lock);

	/* unpin this entry */
	intro_db_put(idb);

out_introspector:
	/* unpin the introspector mm */
	mmput(introspector);
}

static void tdb_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	struct target_db *tdb = container_of(mn, struct target_db, mn);

	pr_debug("%s: mm %016lx\n", __func__, (unsigned long)mm);

	/*
	 * at this point other threads may already have hold of this tdb
	 */
	target_db_extract(tdb);
	target_db_put(tdb);
}

static void idb_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	struct intro_db *idb = container_of(mn, struct intro_db, mn);

	pr_debug("%s: mm %016lx\n", __func__, (unsigned long)mm);

	/*
	 * at this point other threads may already have hold of this idb
	 */
	intro_db_extract(idb);
	intro_db_put(idb);
}

static struct vm_area_struct *
isolate_page_vma(struct vm_area_struct *vma, unsigned long addr)
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
		if (unlikely(vma == NULL))
			return ERR_PTR(-ENOENT);

		/* corner case (again) */
		if (vma_pages(vma) == 1)
			return vma;
	}

	result = split_vma(vma->vm_mm, vma, addr + PAGE_SIZE, true);
	if (IS_ERR_VALUE((long)result))
		return ERR_PTR((long)result);

	vma = find_vma(vma->vm_mm, addr);
	if (unlikely(vma == NULL))
		return ERR_PTR(-ENOENT);

	BUG_ON(vma_pages(vma) != 1);

	return vma;
}

/*
 * Lightweight version of vma_merge() to reduce the internal fragmentation of
 * the mapping process' address space. It merges small VMAs that emerged by
 * splitting a larger VMA with the function above.
 */
static int merge_page_vma(struct vm_area_struct *vma)
{
	struct vm_area_struct *prev = vma->vm_prev;
	struct vm_area_struct *next = vma->vm_next;
	int result = 0;

	if (prev->vm_end == vma->vm_start && prev->anon_vma == vma->anon_vma &&
		prev->vm_flags == vma->vm_flags)
		result = __vma_adjust(prev, prev->vm_start, vma->vm_end,
			prev->vm_pgoff, NULL, vma);

	if (unlikely(result != 0))
		return result;

	if (vma->vm_end == next->vm_start && vma->anon_vma == next->anon_vma &&
		vma->vm_flags == next->vm_flags)
		result = __vma_adjust(vma, vma->vm_start, next->vm_end,
			vma->vm_pgoff, NULL, next);

	return result;
}

static int mm_remote_replace_pte(struct vm_area_struct *map_vma,
				 unsigned long map_hva, struct page *map_page,
				 struct page *new_page)
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

	/* the caller needs to hold the pte lock */
	page_remove_rmap(map_page, false);

	/* create new PTE based on requested page */
	if (new_page != NULL) {
		newpte = mk_pte(new_page, map_vma->vm_page_prot);
		if (map_vma->vm_flags & VM_WRITE)
			newpte = pte_mkwrite(pte_mkdirty(newpte));
	} else
		newpte.pte = 0;

	flush_cache_page(map_vma, map_hva, pte_pfn(*ptep));
	ptep_clear_flush_notify(map_vma, map_hva, ptep);
	set_pte_at_notify(map_mm, map_hva, ptep, newpte);

	pte_unmap_unlock(ptep, ptl);

	mmu_notifier_invalidate_range_end(map_mm, mmun_start, mmun_end);

	return 0;
}

static void mm_remote_put_req(struct page *req_page,
	struct anon_vma *req_anon_vma)
{
	if (req_anon_vma)
		put_anon_vma(req_anon_vma);

	/* get_user_pages_remote() incremented page reference count */
	if (req_page)
		put_page(req_page);
}

static int mm_remote_get_req(struct mm_struct *req_mm, unsigned long req_hva,
			     struct page **preq_page,
			     struct anon_vma **preq_anon_vma)
{
	struct page *req_page = NULL;
	struct anon_vma *req_anon_vma = NULL;
	struct vm_area_struct *req_vma = NULL;
	long nrpages;
	int result = 0;

	down_read(&req_mm->mmap_sem);

	/* get host page corresponding to requested address */
	nrpages = get_user_pages_remote(NULL, req_mm,
		req_hva, 1, FOLL_WRITE | FOLL_SPLIT,
		&req_page, &req_vma, NULL);
	if (unlikely(nrpages == 0)) {
		pr_err("intro: no page for req_hva %016lx\n", req_hva);
		result = -ENOENT;
		goto out_err;
	} else if (IS_ERR_VALUE(nrpages)) {
		result = nrpages;
		pr_err("intro: get_user_pages_remote() failed: %d\n", result);
		goto out_err;
	}

	/* limit introspection to anon memory */
	if (!PageAnon(req_page)) {
		result = -EINVAL;
		pr_err("intro: page at req_hva %016lx not anon\n", req_hva);
		goto out_err;
	}

	/* take & lock this anon vma */
	req_anon_vma = page_get_anon_vma(req_page);
	if (unlikely(req_anon_vma == NULL)) {
		result = -EINVAL;
		pr_err("intro: no anon vma for req_hva %016lx\n", req_hva);
		goto out_err;
	}

	/* output these values only if successful */
	*preq_page = req_page;
	*preq_anon_vma = req_anon_vma;

out_err:
	/* error handling local to the function */
	if (result)
		mm_remote_put_req(req_page, req_anon_vma);

	up_read(&req_mm->mmap_sem);

	return result;
}

static int mm_remote_remap(struct mm_struct *map_mm, unsigned long map_hva,
			   struct page *req_page, struct anon_vma *req_anon_vma)
{
	struct vm_area_struct *map_vma;
	struct page *map_page = NULL;
	int result = 0;

	/* VMA will be modified */
	down_write(&map_mm->mmap_sem);

	/* find VMA containing address */
	map_vma = find_vma(map_mm, map_hva);
	if (unlikely(map_vma == NULL)) {
		pr_err("intro: no local VMA found for remapping\n");
		result = -ENOENT;
		goto out_finalize;
	}

	/* split local VMA for rmap redirecting */
	map_vma = isolate_page_vma(map_vma, map_hva);
	if (IS_ERR_VALUE(map_vma)) {
		result = PTR_ERR(map_vma);
		pr_debug("%s: isolate_page_vma() failed: %d\n",
			__func__, result);
		goto out_finalize;
	}

	/* find (not get) local page corresponding to target address */
	map_page = follow_page(map_vma, map_hva, FOLL_SPLIT);
	if (IS_ERR_VALUE(map_page)) {
		result = PTR_ERR(map_page);
		pr_debug("%s: follow_page() failed: %d\n",
			__func__, result);
		goto out_finalize;
	}

	/* TODO: I assumed before that this page can be NULL in case a mapping
	 * request reuses the address that was left empty by a previous unmap,
	 * but I have never seen this case in practice
	 */
	if (unlikely(map_page == NULL)) {
		pr_err("intro: no local page found for remapping\n");
		result = -ENOENT;
		goto out_finalize;
	}

	/* decouple anon_vma from small VMA; the original anon_vma will be kept
	 * as backup in vm_private_data and restored when the mapping is undone
	 */
	map_vma->vm_private_data = map_vma->anon_vma;
	unlink_anon_vmas(map_vma);
	map_vma->anon_vma = NULL;

	/* temporary anon_vma_lock_write()s req_anon_vma */
	result = anon_vma_assign(map_vma, req_anon_vma);
	if (IS_ERR_VALUE((long)result))
		goto out_noanon;

	/* We're done working with this anon_vma, unpin it.
	 * TODO: is it safe to assume that as long as the degree was incremented
	 * during anon_vma_assign(), this anon_vma won't be released right
	 * after this call ??!
	 */
	put_anon_vma(req_anon_vma);
	req_anon_vma = NULL;	/* guard against mm_remote_put_req() */

	lock_page(req_page);
	mlock_vma_page(req_page);
	unlock_page(req_page);

	/* redirect PTE - this function can fail before altering any PTE */
	result = mm_remote_replace_pte(map_vma, map_hva, map_page, req_page);
	if (IS_ERR_VALUE((long)result))
		goto out_nopte;

	/* increment PTE mappings as a result of referencing req_page */
	atomic_inc(&req_page->_mapcount);

	/* release this page only after references to it have been cleared */
	free_page_and_swap_cache(map_page);

	atomic_inc(&map_count);
	up_write(&map_mm->mmap_sem);

	return 0;

out_nopte:
	/* map_vma->anon_vma will be req_anon_vma */
	unlink_anon_vmas(map_vma);
	map_vma->anon_vma = NULL;

out_noanon:
	/* map_vma->anon_vma will be NULL at this point */
	anon_vma_assign(map_vma, map_vma->vm_private_data);
	map_vma->vm_private_data = NULL;
	merge_page_vma(map_vma);

out_finalize:
	/* just unpin these - req_anon_vma can be NULL */
	mm_remote_put_req(req_page, req_anon_vma);

	up_write(&map_mm->mmap_sem);

	return result;
}

static int mm_remote_map_action(struct mm_struct *req_mm, unsigned long req_hva,
				struct mm_struct *map_mm, unsigned long map_hva)
{
	struct page *req_page;
	struct anon_vma *req_anon_vma;
	int result;

	result = mm_remote_get_req(req_mm, req_hva, &req_page, &req_anon_vma);
	if (IS_ERR_VALUE((long)result))
		return result;

	/* does its own error recovery */
	result = mm_remote_remap(map_mm, map_hva, req_page, req_anon_vma);
	if (IS_ERR_VALUE((long)result))
		return result;

	return 0;
}

int mm_remote_map(struct mm_struct *req_mm, unsigned long req_hva,
		  unsigned long map_hva)
{
	struct mm_struct *map_mm = current->mm;
	struct page_db *pdb = NULL;
	int result = 0;

	pr_debug("%s: req_mm %016lx, req_hva %016lx, map_hva %016lx\n",
		__func__, (unsigned long)req_mm, (unsigned long)req_hva,
		map_hva);

	/* try to pin the target MM so it won't go away (map_mm is ours) */
	if (!mmget_not_zero(req_mm))
		return -EINVAL;

	/* reserve mapping entry in the introspector */
	result = page_db_reserve(map_mm, map_hva, req_mm, req_hva,  &pdb);
	if (IS_ERR_VALUE((long)result))
		goto out;

	/* do the actual memory mapping */
	result = mm_remote_map_action(req_mm, req_hva, map_mm, map_hva);
	if (IS_ERR_VALUE((long)result)) {
		page_db_unreserve(map_mm, pdb);
		goto out;
	}

	/* add mapping to target database */
	result = page_db_add_target(pdb, req_mm, map_mm);
	if (IS_ERR_VALUE((long)result)) {
		mm_remote_unmap_action(map_mm, map_hva);
		page_db_unreserve(map_mm, pdb);
		goto out;
	}

	/* we're done working with this one */
	page_db_release(pdb);

out:
	mmput(req_mm);

	return result;
}
EXPORT_SYMBOL_GPL(mm_remote_map);

static int mm_remote_unmap_action(struct mm_struct *map_mm,
				  unsigned long map_hva)
{
	struct vm_area_struct *map_vma;
	struct page *req_page = NULL;
	int result;

	/* VMA will be modified */
	down_write(&map_mm->mmap_sem);

	/* find destination VMA for mapping */
	map_vma = find_vma(map_mm, map_hva);
	if (unlikely(map_vma == NULL)) {
		result = -ENOENT;
		pr_err("intro: no local VMA found for unmapping\n");
		goto out_err;
	}

	/* find (not get) page mapped to destination address */
	req_page = follow_page(map_vma, map_hva, 0);
	if (IS_ERR_VALUE(req_page)) {
		result = PTR_ERR(req_page);
		req_page = NULL;
		pr_err("intro: follow_page() failed: %d\n", result);
		goto out_err;
	} else if (unlikely(req_page == NULL)) {
		result = -ENOENT;
		pr_err("intro: follow_page() returned no page\n");
		goto out_err;
	}

	/* page table fixing here */
	result = mm_remote_replace_pte(map_vma, map_hva, req_page, NULL);
	if (IS_ERR_VALUE((long)result))
		goto out_err;

	/* decouple links to anon_vmas & restore original anon_vma */
	unlink_anon_vmas(map_vma);
	map_vma->anon_vma = NULL;

	/* this function can fail before setting the anon_vma */
	result = anon_vma_assign(map_vma, map_vma->vm_private_data);
	if (IS_ERR_VALUE((long)result))
		goto out_err;
	map_vma->vm_private_data = NULL;

	/* now try merging the empty VMA with its neighbours */
	result = merge_page_vma(map_vma);
	if (IS_ERR_VALUE((long)result))
		pr_err("intro: merge_page_vma() failed: %d\n", result);

	lock_page(req_page);
	munlock_vma_page(req_page);
	unlock_page(req_page);

	/* reference count was inc during get_user_pages_remote() */
	free_page_and_swap_cache(req_page);
	dec_mm_counter(map_mm, MM_ANONPAGES);

	BUG_ON(atomic_add_negative(-1, &map_count));
	goto out_finalize;

out_err:
	/* reference count was inc during get_user_pages_remote() */
	if (req_page != NULL)
		put_page(req_page);

out_finalize:
	up_write(&map_mm->mmap_sem);

	return result;
}

int mm_remote_unmap(unsigned long map_hva)
{
	struct mm_struct *map_mm = current->mm;
	struct page_db *pdb;
	int result;

	pr_debug("%s: map_hva %016lx\n", __func__, map_hva);

	/* lookup mapping in the introspector database */
	result = page_db_acquire(map_mm, map_hva, &pdb);
	if (IS_ERR_VALUE((long)result))
		return result;

	/* the unmapping is done on local mm only */
	result = mm_remote_unmap_action(map_mm, map_hva);
	if (IS_ERR_VALUE((long)result))
		pr_debug("%s: mm_remote_unmap_action() failed: %d\n",
			__func__, result);

	result = page_db_remove_target(pdb);
	if (IS_ERR_VALUE((long)result))
		pr_debug("%s: page_db_remove_target() failed: %d\n",
			__func__, result);

	result = page_db_unreserve(map_mm, pdb);
	if (IS_ERR_VALUE((long)result))
		pr_debug("%s: page_db_unreserve() failed: %d\n",
			__func__, result);

	return result;
}
EXPORT_SYMBOL_GPL(mm_remote_unmap);

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
}

static void __exit mm_remote_debugfs_exit(void)
{
	debugfs_remove_recursive(mm_remote_debugfs_dir);
}
#else /* CONFIG_DEBUG_FS */
static void __init mm_remote_debugfs_init(void)
{
}

static void __exit mm_remote_debugfs_exit(void)
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

static void __exit mm_remote_exit(void)
{
	mm_remote_debugfs_exit();

	/* number of mappings & unmappings must match */
	BUG_ON(atomic_read(&map_count) != 0);

	/* check for leaks */
	BUG_ON(atomic_read(&pdb_count) != 0);
}

module_init(mm_remote_init);
module_exit(mm_remote_exit);
MODULE_LICENSE("GPL");
