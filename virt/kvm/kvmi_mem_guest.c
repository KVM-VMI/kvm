// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection guest implementation
 *
 * Copyright (C) 2017 Bitdefender S.R.L.
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
#include <linux/mman.h>
#include <linux/types.h>
#include <linux/kvm_host.h>
#include <linux/kvm_para.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/rmap.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <uapi/linux/kvmi.h>
#include <asm/kvmi_guest.h>

#define ASSERT(exp) BUG_ON(!(exp))


static struct list_head file_list;
static spinlock_t file_lock;

struct file_map {
	struct list_head file_list;
	struct file *file;
	struct list_head map_list;
	struct mutex lock;
	bool active;	/* for tearing down */
};

struct page_map {
	struct list_head map_list;
	__u64 gpa;
	unsigned long vaddr;
	unsigned long paddr;
};


static int kvm_dev_open(struct inode *inodep, struct file *filp)
{
	struct file_map *fmp;

	pr_debug("kvmi: file %016lx opened by process %s\n",
		 (unsigned long) filp, current->comm);

	/* link the file 1:1 with such a structure */
	fmp = kmalloc(sizeof(*fmp), GFP_KERNEL);
	if (fmp == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&fmp->file_list);
	fmp->file = filp;
	filp->private_data = fmp;
	INIT_LIST_HEAD(&fmp->map_list);
	mutex_init(&fmp->lock);
	fmp->active = true;

	/* add the entry to the global list */
	spin_lock(&file_lock);
	list_add_tail(&fmp->file_list, &file_list);
	spin_unlock(&file_lock);

	return 0;
}

/* actually does the mapping of a page */
static long _do_mapping(struct kvmi_mem_map *map_req, struct page_map *pmp)
{
	unsigned long paddr;
	struct vm_area_struct *vma;
	struct page *page;
	long result;

	pr_debug("kvmi: mapping remote GPA %016llx into %016llx\n",
		 map_req->gpa, map_req->gva);

	/* check access to memory location */
	if (!access_ok(VERIFY_READ, map_req->gva, PAGE_SIZE)) {
		pr_err("kvmi: invalid virtual address for mapping\n");
		return -EINVAL;
	}

	down_read(&current->mm->mmap_sem);

	/* find the page to be replaced */
	vma = find_vma(current->mm, map_req->gva);
	if (IS_ERR_OR_NULL(vma)) {
		result = PTR_ERR(vma);
		pr_err("kvmi: find_vma() failed with result %ld\n", result);
		goto out;
	}

	page = follow_page(vma, map_req->gva, 0);
	if (IS_ERR_OR_NULL(page)) {
		result = PTR_ERR(page);
		pr_err("kvmi: follow_page() failed with result %ld\n", result);
		goto out;
	}

	if (IS_ENABLED(CONFIG_DEBUG_VM))
		dump_page(page, "page to map_req into");

	WARN(is_zero_pfn(page_to_pfn(page)), "zero-page still mapped");

	/* get the physical address and store it in page_map */
	paddr = page_to_phys(page);
	pr_debug("kvmi: page phys addr %016lx\n", paddr);
	pmp->paddr = paddr;

	/* last thing to do is host mapping */
	result = kvmi_arch_map_hc(&map_req->token, map_req->gpa, paddr);
	if (IS_ERR_VALUE(result)) {
		pr_err("kvmi: HC failed with result %ld\n", result);
		goto out;
	}

out:
	up_read(&current->mm->mmap_sem);

	return result;
}

/* actually does the unmapping of a page */
static long _do_unmapping(unsigned long paddr)
{
	long result;

	pr_debug("kvmi: unmapping request for phys addr %016lx\n", paddr);

	/* local GPA uniquely identifies the mapping on the host */
	result = kvmi_arch_unmap_hc(paddr);
	if (IS_ERR_VALUE(result))
		pr_warn("kvmi: HC failed with result %ld\n", result);

	return result;
}

static long kvm_dev_ioctl_map(struct file_map *fmp, struct kvmi_mem_map *map)
{
	struct page_map *pmp;
	long result;

	if (!access_ok(VERIFY_READ, map->gva, PAGE_SIZE))
		return -EINVAL;
	if (!access_ok(VERIFY_WRITE, map->gva, PAGE_SIZE))
		return -EINVAL;

	/* prepare list entry */
	pmp = kmalloc(sizeof(*pmp), GFP_KERNEL);
	if (pmp == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&pmp->map_list);
	pmp->gpa = map->gpa;
	pmp->vaddr = map->gva;

	/* acquire the file mapping */
	mutex_lock(&fmp->lock);

	/* check if other thread is closing the file */
	if (!fmp->active) {
		result = -ENODEV;
		pr_warn("kvmi: unable to map, file is being closed\n");
		goto out_err;
	}

	/* do the actual mapping */
	result = _do_mapping(map, pmp);
	if (IS_ERR_VALUE(result))
		goto out_err;

	/* link to list */
	list_add_tail(&pmp->map_list, &fmp->map_list);

	/* all fine */
	goto out_finalize;

out_err:
	kfree(pmp);

out_finalize:
	mutex_unlock(&fmp->lock);

	return result;
}

static long kvm_dev_ioctl_unmap(struct file_map *fmp, unsigned long vaddr)
{
	struct list_head *cur;
	struct page_map *pmp;
	bool found = false;
	long result = 0;

	/* acquire the file */
	mutex_lock(&fmp->lock);

	/* check if other thread is closing the file */
	if (!fmp->active) {
		result = -ENODEV;
		pr_warn("kvmi: unable to unmap, file is being closed\n");
		goto out_err;
	}

	/* check that this address belongs to us */
	list_for_each(cur, &fmp->map_list) {
		pmp = list_entry(cur, struct page_map, map_list);

		/* found */
		if (pmp->vaddr == vaddr) {
			found = true;
			break;
		}
	}

	/* not found ? */
	if (!found) {
		result = -ENOENT;
		pr_err("kvmi: address %016lx not mapped\n", vaddr);
		goto out_err;
	}

	/* decouple guest mapping */
	list_del(&pmp->map_list);

out_err:
	mutex_unlock(&fmp->lock);

	if (found) {
		/* unmap & ignore result */
		_do_unmapping(pmp->paddr);

		/* free guest mapping */
		kfree(pmp);
	}

	return result;
}

static long kvm_dev_ioctl(struct file *filp,
			  unsigned int ioctl, unsigned long arg)
{
	void __user *argp = (void __user *) arg;
	struct file_map *fmp;
	long result;

	/* minor check */
	fmp = filp->private_data;
	ASSERT(fmp->file == filp);

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
		pr_err("kvmi: ioctl %d not implemented\n", ioctl);
		result = -ENOTTY;
	}

	return result;
}

static int kvm_dev_release(struct inode *inodep, struct file *filp)
{
	struct file_map *fmp;
	struct list_head *cur, *next;
	struct page_map *pmp;

	pr_debug("kvmi: file %016lx closed by process %s\n",
		 (unsigned long) filp, current->comm);

	/* acquire the file */
	fmp = filp->private_data;
	mutex_lock(&fmp->lock);

	/* mark for teardown */
	fmp->active = false;

	/* release mappings taken on this instance of the file */
	list_for_each_safe(cur, next, &fmp->map_list) {
		pmp = list_entry(cur, struct page_map, map_list);

		/* unmap address */
		_do_unmapping(pmp->paddr);

		/* decouple & free guest mapping */
		list_del(&pmp->map_list);
		kfree(pmp);
	}

	/* done processing this file mapping */
	mutex_unlock(&fmp->lock);

	/* decouple file mapping */
	spin_lock(&file_lock);
	list_del(&fmp->file_list);
	spin_unlock(&file_lock);

	/* free it */
	kfree(fmp);

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

int __init kvm_intro_guest_init(void)
{
	int result;

	if (!kvm_para_available()) {
		pr_err("kvmi: paravirt not available\n");
		return -EPERM;
	}

	result = misc_register(&kvm_mem_dev);
	if (result) {
		pr_err("kvmi: misc device register failed: %d\n", result);
		return result;
	}

	INIT_LIST_HEAD(&file_list);
	spin_lock_init(&file_lock);

	pr_info("kvmi: guest memory introspection device created\n");

	return 0;
}

void kvm_intro_guest_exit(void)
{
	misc_deregister(&kvm_mem_dev);
}

module_init(kvm_intro_guest_init)
module_exit(kvm_intro_guest_exit)
