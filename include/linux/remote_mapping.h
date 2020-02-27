/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _REMOTE_MAPPING_H
#define _REMOTE_MAPPING_H

#include <linux/mm.h>
#include <linux/rmap.h>
#include <linux/rbtree.h>
#include <linux/mmu_notifier.h>
#include <linux/mmdebug.h>

struct page_db {
	struct mm_struct *target;		/* target for this mapping */
	unsigned long req_hva;			/* HVA in target */
	unsigned long map_hva;			/* HVA in client */

	refcount_t refcnt;			/* client-side sharing */
	int flags;

	/* target links - serialized by target_db->lock */
	struct list_head target_link;		/* target-side link */

	/* client links - serialized by client_db->lock */
	struct rb_node file_link;		/* uses map_hva as key */

	/* rmap components - serialized by page lock */
	struct anon_vma *req_anon_vma;
	struct anon_vma *map_anon_vma;
};

struct target_db {
	struct mm_struct *mm;		/* mm of this struct */
	struct hlist_node db_link;	/* database link */

	struct mmu_notifier mn;		/* for notifications from mm */
	struct rcu_head	rcu;		/* for delayed freeing */
	refcount_t refcnt;

	spinlock_t lock;		/* lock for the following */
	struct mm_struct *client;	/* client for this target */
	struct list_head pages_list;	/* mapped HVAs for this target */
};

struct file_db;
struct client_db {
	struct mm_struct *mm;		/* mm of this struct */
	struct hlist_node db_link;	/* database link */

	struct mmu_notifier mn;		/* for notifications from mm */
	struct rcu_head	rcu;		/* for delayed freeing */
	refcount_t refcnt;

	struct file_db *pseudo;		/* kernel interface */
};

struct file_db {
	struct client_db *cdb;

	spinlock_t lock;		/* lock for the following */
	struct rb_root rb_root;		/* mappings indexed by map_hva */
};

static inline void *PageMapping(struct page_db *pdb)
{
	return (void *)pdb + (PAGE_MAPPING_ANON | PAGE_MAPPING_REMOTE);
}

static inline struct page_db *RemoteMapping(struct page *page)
{
	VM_BUG_ON_PAGE(!PageRemote(page), page);
	return (void *)((unsigned long)page->mapping & ~PAGE_MAPPING_FLAGS);
}

/*
 * Template for keyed RB tree.
 *
 * RBCTYPE	type of container structure
 * _rb_root	name of rb_root element
 * RBNTYPE	type of node structure
 * _rb_node	name of rb_node element
 * _key		name of key element
 */

#define KEYED_RB_TREE(RBPREFIX, RBCTYPE, _rb_root, RBNTYPE, _rb_node, _key)\
									\
static bool RBPREFIX ## _insert(RBCTYPE *_container, RBNTYPE *_node)	\
{									\
	struct rb_root *root = &_container->_rb_root;			\
	struct rb_node **new = &root->rb_node;				\
	struct rb_node *parent = NULL;					\
									\
	/* Figure out where to put new node */				\
	while (*new) {							\
		RBNTYPE *this = rb_entry(*new, RBNTYPE, _rb_node);	\
									\
		parent = *new;						\
		if (_node->_key < this->_key)				\
			new = &((*new)->rb_left);			\
		else if (_node->_key > this->_key)			\
			new = &((*new)->rb_right);			\
		else							\
			return false;					\
	}								\
									\
	/* Add new node and rebalance tree. */				\
	rb_link_node(&_node->_rb_node, parent, new);			\
	rb_insert_color(&_node->_rb_node, root);			\
									\
	return true;							\
}									\
									\
static RBNTYPE *							\
RBPREFIX ## _search(RBCTYPE *_container, unsigned long _key)		\
{									\
	struct rb_root *root = &_container->_rb_root;			\
	struct rb_node *node = root->rb_node;				\
									\
	while (node) {							\
		RBNTYPE *_node = rb_entry(node, RBNTYPE, _rb_node);	\
									\
		if (_key < _node->_key)					\
			node = node->rb_left;				\
		else if (_key > _node->_key)				\
			node = node->rb_right;				\
		else							\
			return _node;					\
	}								\
									\
	return NULL;							\
}									\
									\
static void RBPREFIX ## _remove(RBCTYPE *_container, RBNTYPE *_node)	\
{									\
	rb_erase(&_node->_rb_node, &_container->_rb_root);		\
	RB_CLEAR_NODE(&_node->_rb_node);				\
}									\
									\
static bool RBPREFIX ## _empty(const RBCTYPE *_container)		\
{									\
	return RB_EMPTY_ROOT(&_container->_rb_root);			\
}									\

#ifdef CONFIG_REMOTE_MAPPING
extern int mm_remote_map(struct mm_struct *req_mm,
			 unsigned long req_hva, unsigned long map_hva);
extern int mm_remote_unmap(unsigned long map_hva);
extern void mm_remote_reset(void);
extern void rmap_walk_remote(struct page *page, struct rmap_walk_control *rwc);
#else /* CONFIG_REMOTE_MAPPING */
static inline int mm_remote_map(struct mm_struct *req_mm,
				unsigned long req_hva, unsigned long map_hva)
{
	return -EINVAL;
}
static inline int mm_remote_unmap(unsigned long map_hva)
{
	return -EINVAL;
}
static inline void mm_remote_reset(void)
{
}
static inline void rmap_walk_remote(struct page *page,
				    struct rmap_walk_control *rwc)
{
}
#endif /* CONFIG_REMOTE_MAPPING */

#endif /* _REMOTE_MAPPING_H */
