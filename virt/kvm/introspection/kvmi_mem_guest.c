// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection guest implementation
 *
 * Copyright (C) 2017-2019 Bitdefender S.R.L.
 *
 * Author:
 *   Mircea Cirjaliu <mcirjaliu@bitdefender.com>
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/types.h>
#include <linux/kvm_types.h>
#include <linux/kvm_para.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rwlock.h>
#include <linux/hashtable.h>
#include <linux/refcount.h>
#include <linux/ioctl.h>

#include <uapi/linux/kvmi.h>
#include <asm/kvmi_guest.h>

#define ASSERT(exp) BUG_ON(!(exp))
#define DB_HASH_BITS 4

static struct kmem_cache *proc_map_cachep;
static struct kmem_cache *file_map_cachep;
static struct kmem_cache *page_map_cachep;

/* process/mm to proc_map */
static DEFINE_HASHTABLE(db_hash, DB_HASH_BITS);
static DEFINE_SPINLOCK(db_hash_lock);

struct proc_map {
	struct mm_struct *mm;		/* database key */
	struct hlist_node db_link;	/* database link */
	refcount_t refcnt;

	struct rb_root entries;		/* mapping entries for this mm */
	rwlock_t entries_lock;
};

struct file_map {
	struct proc_map *proc;

	struct list_head entries;	/* mapping entries for this file */
	spinlock_t entries_lock;
};

struct page_map {
	struct rb_node proc_link;	/* link to struct proc_map */
	struct list_head file_link;	/* link to struct file_map */

	gpa_t gpa;			/* target GPA */
	gva_t vaddr;			/* local GVA */
};

static void proc_map_init(struct proc_map *pmap)
{
	pmap->mm = NULL;
	INIT_HLIST_NODE(&pmap->db_link);
	refcount_set(&pmap->refcnt, 0);

	pmap->entries = RB_ROOT;
	rwlock_init(&pmap->entries_lock);
}

static struct proc_map *proc_map_alloc(void)
{
	struct proc_map *obj;

	obj = kmem_cache_alloc(proc_map_cachep, GFP_KERNEL);
	if (obj != NULL)
		proc_map_init(obj);

	return obj;
}

static void proc_map_free(struct proc_map *pmap)
{
	ASSERT(hlist_unhashed(&pmap->db_link));
	ASSERT(refcount_read(&pmap->refcnt) == 0);
	ASSERT(RB_EMPTY_ROOT(&pmap->entries));

	kmem_cache_free(proc_map_cachep, pmap);
}

static void file_map_init(struct file_map *fmp)
{
	INIT_LIST_HEAD(&fmp->entries);
	spin_lock_init(&fmp->entries_lock);
}

static struct file_map *file_map_alloc(void)
{
	struct file_map *obj;

	obj = kmem_cache_alloc(file_map_cachep, GFP_KERNEL);
	if (obj != NULL)
		file_map_init(obj);

	return obj;
}

static void file_map_free(struct file_map *fmp)
{
	ASSERT(list_empty(&fmp->entries));

	kmem_cache_free(file_map_cachep, fmp);
}

static void page_map_init(struct page_map *pmp)
{
	memset(pmp, 0, sizeof(*pmp));

	RB_CLEAR_NODE(&pmp->proc_link);
	INIT_LIST_HEAD(&pmp->file_link);
}

static struct page_map *page_map_alloc(void)
{
	struct page_map *obj;

	obj = kmem_cache_alloc(page_map_cachep, GFP_KERNEL);
	if (obj != NULL)
		page_map_init(obj);

	return obj;
}

static void page_map_free(struct page_map *pmp)
{
	ASSERT(RB_EMPTY_NODE(&pmp->proc_link));

	kmem_cache_free(page_map_cachep, pmp);
}

static struct proc_map *get_proc_map(void)
{
	struct proc_map *pmap, *allocated;
	struct mm_struct *mm;
	bool found = false;

	if (!mmget_not_zero(current->mm))
		return NULL;
	mm = current->mm;

	allocated = proc_map_alloc();	/* may be NULL */

	spin_lock(&db_hash_lock);

	hash_for_each_possible(db_hash, pmap, db_link, (unsigned long)mm)
		if (pmap->mm == mm && refcount_inc_not_zero(&pmap->refcnt)) {
			found = true;
			break;
		}

	if (!found && allocated != NULL) {
		pmap = allocated;
		allocated = NULL;

		pmap->mm = mm;
		hash_add(db_hash, &pmap->db_link, (unsigned long)mm);
		refcount_set(&pmap->refcnt, 1);
	} else
		mmput(mm);

	spin_unlock(&db_hash_lock);

	if (allocated != NULL)
		proc_map_free(allocated);

	return pmap;
}

static void put_proc_map(struct proc_map *pmap)
{
	if (refcount_dec_and_test(&pmap->refcnt)) {
		mmput(pmap->mm);

		/* remove from hash table */
		spin_lock(&db_hash_lock);
		hash_del(&pmap->db_link);
		spin_unlock(&db_hash_lock);

		proc_map_free(pmap);
	}
}

static bool proc_map_insert(struct proc_map *pmap, struct page_map *pmp)
{
	struct rb_root *root = &pmap->entries;
	struct rb_node **new = &root->rb_node;
	struct rb_node *parent = NULL;
	struct page_map *this;
	bool inserted = true;

	write_lock(&pmap->entries_lock);

	/* Figure out where to put new node */
	while (*new) {
		this = rb_entry(*new, struct page_map, proc_link);

		parent = *new;
		if (pmp->vaddr < this->vaddr)
			new = &((*new)->rb_left);
		else if (pmp->vaddr > this->vaddr)
			new = &((*new)->rb_right);
		else {
			/* Already have this address */
			inserted = false;
			goto out;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&pmp->proc_link, parent, new);
	rb_insert_color(&pmp->proc_link, root);

out:
	write_unlock(&pmap->entries_lock);

	return inserted;
}

#if 0 /* will use this later */
static struct page_map *proc_map_search(struct proc_map *pmap,
					unsigned long vaddr)
{
	struct rb_root *root = &pmap->entries;
	struct rb_node *node;
	struct page_map *pmp;

	read_lock(&pmap->entries_lock);

	node = root->rb_node;

	while (node) {
		pmp = rb_entry(node, struct page_map, proc_link);

		if (vaddr < pmp->vaddr)
			node = node->rb_left;
		else if (vaddr > pmp->vaddr)
			node = node->rb_right;
		else
			break;
	}

	if (!node)
		pmp = NULL;

	read_unlock(&pmap->entries_lock);

	return pmp;
}
#endif

static struct page_map *proc_map_search_extract(struct proc_map *pmap,
						unsigned long vaddr)
{
	struct rb_root *root = &pmap->entries;
	struct rb_node *node;
	struct page_map *pmp;

	write_lock(&pmap->entries_lock);

	node = root->rb_node;

	while (node) {
		pmp = rb_entry(node, struct page_map, proc_link);

		if (vaddr < pmp->vaddr)
			node = node->rb_left;
		else if (vaddr > pmp->vaddr)
			node = node->rb_right;
		else
			break;
	}

	if (node) {
		rb_erase(&pmp->proc_link, &pmap->entries);
		RB_CLEAR_NODE(&pmp->proc_link);
	} else
		pmp = NULL;

	write_unlock(&pmap->entries_lock);

	return pmp;
}

static void proc_map_remove(struct proc_map *pmap, struct page_map *pmp)
{
	write_lock(&pmap->entries_lock);
	rb_erase(&pmp->proc_link, &pmap->entries);
	RB_CLEAR_NODE(&pmp->proc_link);
	write_unlock(&pmap->entries_lock);
}

static void file_map_insert(struct file_map *fmp, struct page_map *pmp)
{
	spin_lock(&fmp->entries_lock);
	list_add(&pmp->file_link, &fmp->entries);
	spin_unlock(&fmp->entries_lock);
}

static void file_map_remove(struct file_map *fmp, struct page_map *pmp)
{
	spin_lock(&fmp->entries_lock);
	list_del(&pmp->file_link);
	spin_unlock(&fmp->entries_lock);
}

/*
 * Opens the device for map/unmap operations. The mm of this process is
 * associated with these files in a 1:many relationship.
 * Operations on this file must be done within the same process that opened it.
 */
static int kvm_dev_open(struct inode *inodep, struct file *filp)
{
	struct proc_map *pmap;
	struct file_map *fmp;

	pr_debug("kvmi: file %016lx opened by mm %016lx\n",
		 (unsigned long) filp, (unsigned long)current->mm);

	pmap = get_proc_map();
	if (pmap == NULL)
		return -ENOENT;

	/* link the file 1:1 with such a structure */
	fmp = file_map_alloc();
	if (fmp == NULL)
		return -ENOMEM;

	fmp->proc = pmap;
	filp->private_data = fmp;

	return 0;
}

static long _do_mapping(struct kvmi_mem_map *map_req, struct page_map *pmp)
{
	struct page *page;
	phys_addr_t paddr;
	long nrpages;
	long result = 0;

	down_read(&current->mm->mmap_sem);

	/* pin the page to be replaced (also swaps in the page) */
	nrpages = get_user_pages_locked(map_req->gva, 1,
					FOLL_SPLIT | FOLL_MIGRATION,
					&page, NULL);
	if (unlikely(nrpages == 0)) {
		result = -ENOENT;
		pr_err("kvmi: found no page for %016llx\n", map_req->gva);
		goto out;
	} else if (IS_ERR_VALUE(nrpages)) {
		result = nrpages;
		pr_err("kvmi: get_user_pages_locked() failed (%ld)\n", result);
		goto out;
	}

	paddr = page_to_phys(page);
	pr_debug("%s: page phys addr %016llx\n", __func__, paddr);

	/* last thing to do is host mapping */
	result = kvmi_arch_map_hc(&map_req->token, map_req->gpa, paddr);
	if (IS_ERR_VALUE(result)) {
		pr_warn("kvmi: mapping failed for %016llx -> %016lx (%ld)\n",
			pmp->gpa, pmp->vaddr, result);

		/* don't need this page anymore */
		put_page(page);
	}

out:
	up_read(&current->mm->mmap_sem);

	return result;
}

static long _do_unmapping(struct mm_struct *mm, struct page_map *pmp)
{
	struct vm_area_struct *vma;
	struct page *page;
	phys_addr_t paddr;
	long result = 0;

	down_read(&mm->mmap_sem);

	/* find the VMA for the virtual address */
	vma = find_vma(mm, pmp->vaddr);
	if (vma == NULL) {
		result = -ENOENT;
		pr_err("kvmi: find_vma() found no VMA\n");
		goto out;
	}

	/* the page is pinned, thus easy to access */
	page = follow_page(vma, pmp->vaddr, 0);
	if (IS_ERR_VALUE(page)) {
		result = PTR_ERR(page);
		pr_err("kvmi: follow_page() failed (%ld)\n", result);
		goto out;
	} else if (page == NULL) {
		result = -ENOENT;
		pr_err("kvmi: follow_page() found no page\n");
		goto out;
	}

	paddr = page_to_phys(page);
	pr_debug("%s: page phys addr %016llx\n", __func__, paddr);

	/* last thing to do is host unmapping */
	result = kvmi_arch_unmap_hc(paddr);
	if (IS_ERR_VALUE(result))
		pr_warn("kvmi: unmapping failed for %016lx (%ld)\n",
			pmp->vaddr, result);

	/* finally unpin the page */
	put_page(page);

out:
	up_read(&mm->mmap_sem);

	return result;
}

static noinline long kvm_dev_ioctl_map(struct file_map *fmp,
				       struct kvmi_mem_map *map)
{
	struct proc_map *pmap = fmp->proc;
	struct page_map *pmp;
	bool added;
	long result = 0;

	pr_debug("kvmi: mm %016lx map request %016llx -> %016llx\n",
		(unsigned long)current->mm, map->gpa, map->gva);

	if (!access_ok(map->gva, PAGE_SIZE))
		return -EINVAL;

	/* prepare list entry */
	pmp = page_map_alloc();
	if (pmp == NULL)
		return -ENOMEM;

	pmp->gpa = map->gpa;
	pmp->vaddr = map->gva;

	added = proc_map_insert(pmap, pmp);
	if (added == false) {
		result = -EALREADY;
		pr_warn("kvmi: address %016llx already mapped\n", map->gva);
		goto out_free;
	}
	file_map_insert(fmp, pmp);

	/* actual mapping here */
	result = _do_mapping(map, pmp);
	if (IS_ERR_VALUE(result))
		goto out_remove;

	return 0;

out_remove:
	proc_map_remove(pmap, pmp);
	file_map_remove(fmp, pmp);

out_free:
	page_map_free(pmp);

	return result;
}

static noinline long kvm_dev_ioctl_unmap(struct file_map *fmp,
					 unsigned long vaddr)
{
	struct proc_map *pmap = fmp->proc;
	struct page_map *pmp;
	long result = 0;

	pr_debug("kvmi: mm %016lx unmap request %016lx\n",
		(unsigned long)current->mm, vaddr);

	pmp = proc_map_search_extract(pmap, vaddr);
	if (pmp == NULL) {
		pr_warn("kvmi: address %016lx not mapped\n", vaddr);
		return -ENOENT;
	}

	/* actual unmapping here */
	result = _do_unmapping(current->mm, pmp);

	file_map_remove(fmp, pmp);
	page_map_free(pmp);

	return result;
}

/*
 * Operations on this file must be done within the same process that opened it.
 */
static long kvm_dev_ioctl(struct file *filp,
			  unsigned int ioctl, unsigned long arg)
{
	void __user *argp = (void __user *) arg;
	struct file_map *fmp = filp->private_data;
	struct proc_map *pmap = fmp->proc;
	long result;

	/* this helps keep my code simpler */
	if (current->mm != pmap->mm) {
		pr_warn("kvmi: ioctl request by different process\n");
		return -EINVAL;
	}

	switch (ioctl) {
	case KVM_INTRO_MEM_MAP: {
		struct kvmi_mem_map map;

		result = -EFAULT;
		if (copy_from_user(&map, argp, sizeof(map)))
			break;

		result = kvm_dev_ioctl_map(fmp, &map);
		break;
	}
	case KVM_INTRO_MEM_UNMAP: {
		unsigned long vaddr = (unsigned long) arg;

		result = kvm_dev_ioctl_unmap(fmp, vaddr);
		break;
	}
	default:
		pr_warn("kvmi: ioctl %d not implemented\n", ioctl);
		result = -ENOTTY;
	}

	return result;
}

/*
 * No constraint on closing the device.
 */
static int kvm_dev_release(struct inode *inodep, struct file *filp)
{
	struct file_map *fmp = filp->private_data;
	struct proc_map *pmap = fmp->proc;
	struct page_map *pmp, *temp;

	pr_debug("kvmi: file %016lx closed by mm %016lx\n",
		 (unsigned long) filp, (unsigned long)current->mm);

	/* this file_map has no more users, thus no more concurrent access */
	list_for_each_entry_safe(pmp, temp, &fmp->entries, file_link) {
		proc_map_remove(pmap, pmp);
		list_del(&pmp->file_link);

		_do_unmapping(pmap->mm, pmp);

		page_map_free(pmp);
	}

	file_map_free(fmp);
	put_proc_map(pmap);

	return 0;
}

static const struct file_operations kvmmem_ops = {
	.open		= kvm_dev_open,
	.unlocked_ioctl = kvm_dev_ioctl,
	.compat_ioctl   = kvm_dev_ioctl,
	.release	= kvm_dev_release,
};

static struct miscdevice kvm_mem_dev = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "kvmmem",
	.fops		= &kvmmem_ops,
};

static int __init kvm_intro_guest_init(void)
{
	int result = 0;

	if (!kvm_para_available()) {
		pr_warn("kvmi: paravirt not available\n");
		return -EPERM;
	}

	proc_map_cachep = KMEM_CACHE(proc_map, SLAB_PANIC | SLAB_ACCOUNT);
	if (proc_map_cachep == NULL) {
		result = -ENOMEM;
		goto out_err;
	}

	file_map_cachep = KMEM_CACHE(file_map, SLAB_PANIC | SLAB_ACCOUNT);
	if (file_map_cachep == NULL) {
		result = -ENOMEM;
		goto out_err;
	}

	page_map_cachep = KMEM_CACHE(page_map, SLAB_PANIC | SLAB_ACCOUNT);
	if (page_map_cachep == NULL) {
		result = -ENOMEM;
		goto out_err;
	}

	result = misc_register(&kvm_mem_dev);
	if (result) {
		pr_err("kvmi: misc device register failed (%d)\n", result);
		goto out_err;
	}

	pr_debug("kvmi: guest memory introspection device created\n");

	return 0;

out_err:
	kmem_cache_destroy(page_map_cachep);
	kmem_cache_destroy(file_map_cachep);
	kmem_cache_destroy(proc_map_cachep);

	return result;
}

static void __exit kvm_intro_guest_exit(void)
{
	misc_deregister(&kvm_mem_dev);

	kmem_cache_destroy(page_map_cachep);
	kmem_cache_destroy(file_map_cachep);
	kmem_cache_destroy(proc_map_cachep);
}

module_init(kvm_intro_guest_init)
module_exit(kvm_intro_guest_exit)
