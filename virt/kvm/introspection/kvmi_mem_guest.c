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
#include <linux/mount.h>
#include <linux/pseudo_fs.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/types.h>
#include <linux/kvm_types.h>
#include <linux/kvm_para.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/lockdep.h>
#include <linux/refcount.h>
#include <linux/mman.h>
#include <linux/list.h>
#include <linux/notifier.h>
#include <linux/memory.h>
#include <linux/memory_hotplug.h>
#include <linux/uuid.h>
#include <linux/pagemap.h>
#include <linux/pfn_t.h>

#include <uapi/linux/magic.h>
#include <uapi/linux/kvmi.h>
#include <asm/kvmi_guest.h>

#include "kvmi_int.h"

#define ASSERT(exp) BUG_ON(!(exp))


static DECLARE_WAIT_QUEUE_HEAD(ready_wait_queue);

struct kvmi_mem_dev {
	struct device dev;
	struct dev_pagemap pgmap;
	struct resource *res;
	void *addr;
	bool ready;
};

static inline struct kvmi_mem_dev *dev_to_kvmi_mem_dev(struct device *dev)
{
	return container_of(dev, struct kvmi_mem_dev , dev);
}

static inline struct kvmi_mem_dev *pgmap_to_kvmi_mem_dev(struct dev_pagemap *pgmap)
{
	return container_of(pgmap, struct kvmi_mem_dev , pgmap);
}

static struct vfsmount *kvmi_mem_mnt;
static struct super_block *kvmi_mem_superblock;

/* this is assigned to VMA */
struct kvmi_mem_map_range {
	gpa_t req_start;
	size_t req_length;
	gpa_t map_start;

	struct list_head link;
	atomic_t users;
};

/* this is assigned to file */
struct kvmi_mem_map_ctx {
	uuid_t dom_id;
	bool started;

	struct list_head ranges;
	struct mutex lock;

	struct inode inode;
};

static struct kvmi_mem_map_ctx *to_kvmi_mem_ctx(struct inode *inode)
{
	return container_of(inode, struct kvmi_mem_map_ctx, inode);
}

static inline gpa_t kvmi_mem_range_start(struct kvmi_mem_map_range *range)
{
	return range->req_start;
}

static inline gpa_t kvmi_mem_range_end(struct kvmi_mem_map_range *range)
{
	return range->req_start + range->req_length;
}

static int
kvmi_mem_add_range(struct kvmi_mem_map_ctx *ctx, struct kvmi_mem_map *mapinfo)
{
	struct kvmi_mem_map_range *range;

	lockdep_assert_held(&ctx->lock);

	range = kmalloc(sizeof(*range), GFP_KERNEL);
	if (!range)
		return -ENOMEM;

	range->req_start = mapinfo->req_start;
	range->req_length = mapinfo->req_length;
	range->map_start = mapinfo->map_start;

	list_add(&range->link, &ctx->ranges);
	atomic_set(&range->users, 0);

	return 0;
}

static struct kvmi_mem_map_range *
kvmi_mem_find_range(struct kvmi_mem_map_ctx *ctx, gpa_t req_gpa)
{
	struct kvmi_mem_map_range *range;

	lockdep_assert_held(&ctx->lock);

	list_for_each_entry(range, &ctx->ranges, link)
		if (req_gpa >= kvmi_mem_range_start(range) &&
		    req_gpa < kvmi_mem_range_end(range))
			return range;

	return NULL;
}

static void
kvmi_mem_del_range(struct kvmi_mem_map_range *range, struct kvmi_mem_map_ctx *ctx)
{
	struct kvmi_mem_unmap request;
	long result;

	/* this can happen if remap failed in the middle */
	if (range->map_start != 0) {
		/* request unmapping from host */
		uuid_copy(&request.dom_id, &ctx->dom_id);
		request.map_gpa = range->map_start;

		result = kvmi_arch_guest_unmap(&request);
		if (result)
			pr_warn("%s: kvmi_arch_guest_unmap() failed: %ld\n",
				__func__, result);
	}

	/* delete range from database and free */
	list_del(&range->link);
	kfree(range);
}


static vm_fault_t kvmi_mem_vm_fault(struct vm_fault *vmf)
{
	struct kvmi_mem_map_range *range = vmf->vma->vm_private_data;
	struct page *page;
	unsigned long pfn;
	pfn_t pfn_flags;
	int result = 0;

	BUG_ON(range->map_start == 0);
	pfn = PHYS_PFN(range->map_start) + (vmf->pgoff - PHYS_PFN(range->req_start));
	pfn_flags = __pfn_to_pfn_t(pfn, PFN_DEV | PFN_MAP);

	result = vmf_insert_mixed(vmf->vma, vmf->address, pfn_flags);
	if (result != VM_FAULT_NOPAGE)
		return result;

	page = pfn_to_page(pfn);
	BUG_ON(!page);

	/* rmap */
	page->mapping = vmf->vma->vm_file->f_mapping;
	page->index = linear_page_index(vmf->vma, vmf->address);

	return result;
}

/* called internally during kvmi_mem_unmap() */
static void kvmi_mem_vm_close(struct vm_area_struct *vma)
{
	struct kvmi_mem_map_range *range = vma->vm_private_data;

	pr_debug("%s: vma %lx-%lx closing\n", __func__,
		 vma->vm_start, vma->vm_end);

	atomic_dec(&range->users);
}

/* don't allow splitting these VMAs (partial unmap) */
static int kvmi_mem_vm_split(struct vm_area_struct *vma, unsigned long addr)
{
	return -EINVAL;
}

static const struct vm_operations_struct kvmi_mem_vmops = {
	.fault = kvmi_mem_vm_fault,
	.close = kvmi_mem_vm_close,
	.split = kvmi_mem_vm_split,
};

static int kvmi_mem_open(struct inode *inode, struct file *file)
{
	struct kvmi_mem_map_ctx *ctx;
	struct inode *dom_inode;

	pr_debug("%s: file %lx opened\n", __func__, (long)file);

	dom_inode = iget_locked(kvmi_mem_superblock, get_next_ino());
	if (!dom_inode)
		return -ENOMEM;

	ASSERT(dom_inode->i_state & I_NEW);
	ctx = to_kvmi_mem_ctx(dom_inode);

	INIT_LIST_HEAD(&ctx->ranges);
	mutex_init(&ctx->lock);

	file->private_data = ctx;

	dom_inode->i_mode = S_IFCHR;
	dom_inode->i_flags = S_DAX;
	dom_inode->i_rdev = 0;
	dom_inode->i_mapping = &dom_inode->i_data;
	dom_inode->i_mapping->host = dom_inode;
	file->f_mapping = dom_inode->i_mapping;
	mapping_set_gfp_mask(&dom_inode->i_data, GFP_USER);
	unlock_new_inode(dom_inode);

	return 0;
}

/*
 * This will tell the host that introspection started for the given domain ID.
 */
static noinline long kvmi_mem_start(struct file *file)
{
	struct kvmi_mem_map_ctx *ctx = file->private_data;
	long result;

	mutex_lock(&ctx->lock);

	if (ctx->started) {
		pr_err("memory introspection already started\n");
		result = -EALREADY;
		goto out;
	}

	result = kvmi_arch_guest_start(&ctx->dom_id);
	if (result) {
		pr_err("%s: kvmi_arch_guest_start() failed: %d\n",
			__func__, (int) result);
		goto out;
	}

	ctx->started = true;
	pr_debug("%s: domain introspection started\n", __func__);

out:
	mutex_unlock(&ctx->lock);

	return result;
}

/*
 * This will request a mapping from the host.
 * The host will map a memory range from another guest and will hotplug it.
 * The result of the operation will be communicated in the mapinfo struct.
 */
static noinline long kvmi_mem_map(struct file *file,
				  struct kvmi_guest_mem_map *request)
{
	struct kvmi_mem_map_ctx *ctx = file->private_data;
	struct kvmi_mem_map mapinfo;
	struct kvmi_mem_map_range *range;
	long result = 0;

	pr_debug("%s: req gpa %016llx\n", __func__, request->gpa);

	mutex_lock(&ctx->lock);

	if (!ctx->started) {
		pr_err("memory introspection not started\n");
		result = -EINVAL;
		goto out;
	}

	/* test if range was already mapped */
	range = kvmi_mem_find_range(ctx, request->gpa);
	if (range) {
		pr_err("gpa %016llx already mapped in %016llx+%lx\n",
			request->gpa, range->req_start, range->req_length);
		result = -EALREADY;
		goto out;
	}

	/* prepare mapping request args */
	memset(&mapinfo, 0, sizeof(mapinfo));
	uuid_copy(&mapinfo.dom_id, &ctx->dom_id);
	mapinfo.req_gpa = request->gpa;
	mapinfo.min_map = get_hotplug_granularity() << PAGE_SHIFT;

	/* request mapping from host */
	result = kvmi_arch_guest_map(&request->token, &mapinfo);
	if (result) {
		pr_err("%s: kvmi_arch_guest_map(%016llx) failed: %d\n",
			__func__, mapinfo.req_gpa, (int) result);
		goto out;
	}

	pr_debug("%s: HC range start %lx, length %lx, mapped @ %lx\n", __func__,
		(long)mapinfo.req_start, (long)mapinfo.req_length,
		(long)mapinfo.map_start);

	/* add range to database */
	result = kvmi_mem_add_range(ctx, &mapinfo);
	if (result)
		goto out;

	/* return mapped range to the user */
	request->gpa = mapinfo.req_start;
	request->length = mapinfo.req_length;

out:
	mutex_unlock(&ctx->lock);

	return result;
}

static noinline long kvmi_mem_unmap(struct file *file, unsigned long gpa)
{
	struct kvmi_mem_map_ctx *ctx = file->private_data;
	struct kvmi_mem_map_range *range;
	long result = 0;

	pr_debug("%s: gpa %lx\n", __func__, gpa);

	mutex_lock(&ctx->lock);

	if (!ctx->started) {
		pr_err("memory introspection not started\n");
		result = -EINVAL;
		goto out;
	}

	range = kvmi_mem_find_range(ctx, gpa);
	if (!range) {
		pr_err("range starting at %lx not found\n", gpa);
		result = -ENOENT;
		goto out;
	}

	if (range->req_start != gpa) {
		pr_err("range doesn't start at %lx\n", gpa);
		result = -EINVAL;
		goto out;
	}

	if (atomic_read(&range->users) != 0) {
		pr_err("range starting at %lx still used\n", gpa);
		result = -EINVAL;
		goto out;
	}

	/* this wll also do the hypercall */
	kvmi_mem_del_range(range, ctx);

out:
	mutex_unlock(&ctx->lock);

	return result;
}

static long kvmi_mem_ioctl(struct file *file,
			   unsigned int ioctl, unsigned long arg)
{
	long result;

	switch (ioctl) {

	case KVM_GUEST_MEM_START: {
		struct kvmi_mem_map_ctx *ctx = file->private_data;
		void __user *argp = (void __user *) arg;

		result = -EFAULT;
		if (copy_from_user(&ctx->dom_id, argp, sizeof(uuid_t)))
			break;

		result = kvmi_mem_start(file);
		if (result)
			break;

		result = 0;
		break;
	}

	case KVM_GUEST_MEM_MAP: {
		void __user *argp = (void __user *) arg;
		struct kvmi_guest_mem_map request;

		result = -EFAULT;
		if (copy_from_user(&request, argp, sizeof(request)))
			break;

		result = kvmi_mem_map(file, &request);
		if (result)
			break;

		result = -EFAULT;
		if (copy_to_user(argp, &request, sizeof(request)))
			break;

		result = 0;
		break;
	}

	case KVM_GUEST_MEM_UNMAP: {
		unsigned long gpa = arg;
		result = kvmi_mem_unmap(file, gpa);
		break;
	}

	default:
		pr_warn("kvmi: ioctl %d not implemented\n", ioctl);
		result = -ENOTTY;
		break;
	}

	return result;
}

#define ready(__pfn, __pgmap)							\
({										\
	__label__ __out;							\
	bool __result = false;							\
	struct kvmi_mem_dev *__kvmi_dev;					\
										\
	__pgmap = get_dev_pagemap(__pfn, __pgmap);				\
	if (!__pgmap)								\
		goto __out;							\
										\
	__kvmi_dev = pgmap_to_kvmi_mem_dev(__pgmap);				\
	if (__kvmi_dev->ready)							\
		__result = true;						\
										\
__out:	__result;								\
})

static int wait_pgmap_ready(gpa_t phys_addr)
{
	unsigned long pfn;
	struct dev_pagemap *pgmap = NULL;
	int result;

	/* wait for the dev_pgmap containing range to become ready */
	pfn = PHYS_PFN(phys_addr);
	result = wait_event_interruptible(ready_wait_queue, ready(pfn, pgmap));
	if (result) {
		/* pgmap may be pinned, but not yet ready */
		if (pgmap)
			put_dev_pagemap(pgmap);

		return result;
	}

	put_dev_pagemap(pgmap);

	return result;
}

static int kvmi_mem_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct kvmi_mem_map_ctx *ctx = file->private_data;
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	struct kvmi_mem_map_range *range;

	pr_debug("%s: vma %lx-%lx\n", __func__, vma->vm_start, vma->vm_end);

	/* must hit do_shared_fault() */
	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	mutex_lock(&ctx->lock);

	/* look up the database & associate the entry with the VMA */
	range = kvmi_mem_find_range(ctx, offset);
	if (!range) {
		mutex_unlock(&ctx->lock);
		pr_err("range containing %lx not found\n", offset);
		return -EINVAL;
	}
	atomic_inc(&range->users);

	mutex_unlock(&ctx->lock);

	/* set basic VMA properties */
	vma->vm_flags |= VM_DONTCOPY | VM_DONTDUMP | VM_PFNMAP;
	vma->vm_ops = &kvmi_mem_vmops;
	vma->vm_private_data = range;

	/* wait for the dev_pgmap containing range to become ready */
	return wait_pgmap_ready(range->map_start);
}

static int kvmi_mem_release(struct inode *inode, struct file *file)
{
	struct kvmi_mem_map_ctx *ctx = file->private_data;
	struct kvmi_mem_map_range *range, *temp;

	pr_debug("%s: file %lx closing\n", __func__, (long)file);

	/* don't need to take mutex anymore */
	if (!ctx->started)
		goto out;

	/*
	 * maps get established by kvmi_mem_map() !!
	 * maps are torn down by kvmi_mem_unmap() !!
	 * mmap() only gets access to the mapped ranges !!
	 * if we ended up here with mappings still present, undo them
	 *  before calling kvmi_arch_guest_end()
	 */
	if (!list_empty(&ctx->ranges)) {
		list_for_each_entry_safe(range, temp, &ctx->ranges, link)
			kvmi_mem_del_range(range, ctx);
	}

	kvmi_arch_guest_end(&ctx->dom_id);

out:
	mutex_destroy(&ctx->lock);
	iput(&ctx->inode);

	return 0;
}

static const struct file_operations kvmi_mem_fops = {
	.open = kvmi_mem_open,
	.unlocked_ioctl = kvmi_mem_ioctl,
	.compat_ioctl = kvmi_mem_ioctl,
	.mmap = kvmi_mem_mmap,
	.release = kvmi_mem_release,
};

static struct miscdevice kvmi_mem_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "kvmmem",
	.fops = &kvmi_mem_fops,
};


static struct bus_type kvmi_mem_subsys = {
	.name = "kvmi_mem",
	.dev_name = "kvmi_mem",
};

static void kvmi_mem_dev_release(struct device *dev)
{
	struct kvmi_mem_dev *kvmi_dev = dev_to_kvmi_mem_dev(dev);

	pr_debug("%s: kvmi_dev %lx\n", __func__, (long)kvmi_dev);

	kfree(kvmi_dev);
}

static struct kvmi_mem_dev *kvmi_mem_dev_alloc(int nid, u64 start, u64 size)
{
	struct kvmi_mem_dev *kvmi_dev;
	struct device *dev;
	int result;

	kvmi_dev = kzalloc(sizeof(*kvmi_dev), GFP_KERNEL);
	if (!kvmi_dev)
		return ERR_PTR(-ENOMEM);

	dev = &kvmi_dev->dev;
	device_initialize(dev);
	dev->bus = &kvmi_mem_subsys;
	dev->release = kvmi_mem_dev_release;
	dev->offline_disabled = true;
	set_dev_node(dev, nid);
	dev->id = PHYS_PFN(start);
	dev_set_name(dev, "kvmi-mem-%lx", PHYS_PFN(start));

	pr_debug("%s: kvmi_dev %lx\n", __func__, (long)kvmi_dev);

	result = device_add(dev);
	if (result) {
		put_device(dev);
		return ERR_PTR(result);
	}

	return kvmi_dev;
}

static int kvmi_memory_add(int nid, u64 start, u64 size)
{
	struct kvmi_mem_dev *kvmi_dev;
	struct device *dev;
	int result;

	pr_debug("%s: node %d, start %llx, size %llx\n", __func__, nid, start, size);

	kvmi_dev = kvmi_mem_dev_alloc(nid, start, size);
	if (IS_ERR(kvmi_dev))
		return PTR_ERR(kvmi_dev);
	dev = &kvmi_dev->dev;

	kvmi_dev->res = devm_request_mem_region(dev, start, size, "KVMI Mem");
	if (!kvmi_dev->res) {
		pr_err("%s: devm_request_mem_region() failed", __func__);
		result = -EBUSY;
		goto out_dev;
	}

	memcpy(&kvmi_dev->pgmap.res, kvmi_dev->res, sizeof(*kvmi_dev->res));
	kvmi_dev->pgmap.type = MEMORY_DEVICE_DEVDAX;

	kvmi_dev->addr = devm_memremap_pages(dev, &kvmi_dev->pgmap);
	if (IS_ERR(kvmi_dev->addr)) {
		pr_err("%s: devm_memremap_pages() failed", __func__);
		result = PTR_ERR(kvmi_dev->addr);
		goto out_mem;
	}

	kvmi_dev->ready = true;
	// TODO: barrier ??
	wake_up(&ready_wait_queue);

	put_device(dev);		/* usage reference */

	return 0;

out_mem:
	devm_release_mem_region(dev, start, size);
out_dev:
	device_del(dev);
	put_device(dev);

	return result;
}

static int kvmi_memory_remove(int nid, u64 start, u64 size)
{
	struct kvmi_mem_dev *kvmi_dev;
	struct device *dev;
	struct resource *res;

	pr_debug("%s: node %d, start %llx, size %llx\n", __func__, nid, start, size);

	/* look for device */
	dev = subsys_find_device_by_id(&kvmi_mem_subsys, PHYS_PFN(start), NULL);
	if (!dev) {
		pr_warn("%s: subsys_find_device_by_id(%lx) found nothing",
			__func__, PHYS_PFN(start));
		return -ENODEV;
	}

	/* test if device matches range/node */
	kvmi_dev = dev_to_kvmi_mem_dev(dev);
	res = kvmi_dev->res;
	if (res->start != start || resource_size(res) != size ||
		(dev_to_node(dev) != NUMA_NO_NODE && dev_to_node(dev) != nid)) {
		pr_warn("%s: range or node differs", __func__);
		return -EINVAL;
	}

	devm_memunmap_pages(dev, &kvmi_dev->pgmap);
	devm_release_mem_region(dev, start, size);

	device_del(dev);
	put_device(dev);		/* usage reference */

	return 0;
}

static int kvmi_hotplug_notifier(struct notifier_block *nb, unsigned long val, void *v)
{
	struct hotplug_notify *arg = v;
	int ret = 0;

	switch (val) {
	case MEM_ADD:
		ret = kvmi_memory_add(arg->nid, arg->start, arg->size);
		break;

	case MEM_REMOVE:
		ret = kvmi_memory_remove(arg->nid, arg->start, arg->size);
		break;

	default:
		return NOTIFY_DONE;
	}

	if (ret) {
		pr_warn("%s: failed: %d\n", __func__, ret);
		return notifier_from_errno(ret);
	}

	arg->handled = true;
	return NOTIFY_STOP;
}

static struct notifier_block kvmi_hotplug_nb = {
	.notifier_call = kvmi_hotplug_notifier,
	.priority = 1
};


static struct inode *kvmi_mem_alloc_inode(struct super_block *sb)
{
	struct kvmi_mem_map_ctx *ctx;
	struct inode *inode;

	pr_debug("%s: superblock %s\n", __func__, sb->s_id);

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(ENOMEM);

	inode = &ctx->inode;
	inode_init_once(inode);

	return inode;
}

static void kvmi_mem_free_inode(struct inode *inode)
{
	struct kvmi_mem_map_ctx *ctx = to_kvmi_mem_ctx(inode);

	pr_debug("%s: inode %lx\n", __func__, inode->i_ino);

	kfree(ctx);
}

static const struct super_operations kvmi_mem_sops = {
	.statfs = simple_statfs,
	.alloc_inode = kvmi_mem_alloc_inode,
	.free_inode = kvmi_mem_free_inode,
	.drop_inode = generic_delete_inode,
};

static int kvmi_mem_init_fs_context(struct fs_context *fc)
{
	struct pseudo_fs_context *ctx = init_pseudo(fc, KVMIMEM_FS_MAGIC);
	if (!ctx)
		return -ENOMEM;
	ctx->ops = &kvmi_mem_sops;
	return 0;
}

static struct file_system_type kvmi_mem_fs_type = {
	.name = "kvmi_mem",
	.init_fs_context = kvmi_mem_init_fs_context,
	.kill_sb = kill_anon_super,
};


static int __init kvm_intro_guest_init(void)
{
	int result = 0;

	if (!kvm_para_available()) {
		pr_err("paravirt not available, driver won't work\n");
		return -EINVAL;
	}

	result = misc_register(&kvmi_mem_dev);
	if (result) {
		pr_err("misc_register() failed: %d\n", result);
		return result;
	}

	kvmi_mem_subsys.dev_root = root_device_register("kvmi_mem");
	if (!kvmi_mem_subsys.dev_root) {
		pr_err("root_device_register() failed: %d\n", result);
		goto out_dev;
	}

	result = bus_register(&kvmi_mem_subsys);
	if (result) {
		pr_err("subsys_system_register() failed: %d\n", result);
		goto out_root;
	}

	result = register_hotplug_notifier(&kvmi_hotplug_nb);
	if (result) {
		pr_err("subsys_system_register() failed: %d\n", result);
		goto out_bus;
	}

	kvmi_mem_mnt = kern_mount(&kvmi_mem_fs_type);
	if (IS_ERR(kvmi_mem_mnt)) {
		result = PTR_ERR(kvmi_mem_mnt);
		goto out_ntf;
	}
	kvmi_mem_superblock = kvmi_mem_mnt->mnt_sb;

	pr_debug("memory introspect dev created\n");

	return 0;

out_ntf:
	unregister_hotplug_notifier(&kvmi_hotplug_nb);
out_bus:
	bus_unregister(&kvmi_mem_subsys);
out_root:
	root_device_unregister(kvmi_mem_subsys.dev_root);
out_dev:
	misc_deregister(&kvmi_mem_dev);

	return result;
}

static void __exit kvm_intro_guest_exit(void)
{
	kern_unmount(kvmi_mem_mnt);

	unregister_hotplug_notifier(&kvmi_hotplug_nb);

	bus_unregister(&kvmi_mem_subsys);

	misc_deregister(&kvmi_mem_dev);
}

module_init(kvm_intro_guest_init)
module_exit(kvm_intro_guest_exit)
