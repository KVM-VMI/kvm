// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection
 *
 * Copyright (C) 2017-2019 Bitdefender S.R.L.
 *
 */
#include <linux/mmu_context.h>
#include <uapi/linux/kvmi.h>
#include "kvmi_int.h"
#include <linux/kthread.h>
#include <linux/bitmap.h>
#include <linux/remote_mapping.h>

#define CREATE_TRACE_POINTS
#include <trace/events/kvmi.h>

#define MAX_PAUSE_REQUESTS 1001

static struct kmem_cache *msg_cache;
static struct kmem_cache *radix_cache;
static struct kmem_cache *job_cache;

static bool kvmi_create_vcpu_event(struct kvm_vcpu *vcpu);
static void kvmi_abort_events(struct kvm *kvm);
static bool kvmi_track_preread(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
	u8 *new, int bytes, struct kvm_page_track_notifier_node *node,
	bool *data_ready);
static bool kvmi_track_prewrite(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
	const u8 *new, int bytes, struct kvm_page_track_notifier_node *node);
static bool kvmi_track_preexec(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
	struct kvm_page_track_notifier_node *node);
static void kvmi_track_create_slot(struct kvm *kvm,
	struct kvm_memory_slot *slot, unsigned long npages,
	struct kvm_page_track_notifier_node *node);
static void kvmi_track_flush_slot(struct kvm *kvm, struct kvm_memory_slot *slot,
	struct kvm_page_track_notifier_node *node);

static const u8 full_access  =	KVMI_PAGE_ACCESS_R |
				KVMI_PAGE_ACCESS_W |
				KVMI_PAGE_ACCESS_X;
static const u32 default_write_access_bitmap;

void *kvmi_msg_alloc(void)
{
	return kmem_cache_zalloc(msg_cache, GFP_KERNEL);
}

void *kvmi_msg_alloc_check(size_t size)
{
	if (size > KVMI_MSG_SIZE_ALLOC)
		return NULL;
	return kvmi_msg_alloc();
}

void kvmi_msg_free(void *addr)
{
	if (addr)
		kmem_cache_free(msg_cache, addr);
}

static struct kvmi_mem_access *__kvmi_get_gfn_access(struct kvmi *ikvm,
						     const gfn_t gfn)
{
	return radix_tree_lookup(&ikvm->access_tree, gfn);
}

/*
 * TODO: intercept any SPP change made on pages present in our radix tree.
 *
 * bitmap must have the same value as the corresponding SPPT entry.
 */
static int kvmi_get_gfn_access(struct kvmi *ikvm, const gfn_t gfn,
			       u8 *access, u32 *write_bitmap)
{
	struct kvmi_mem_access *m;

	*write_bitmap = default_write_access_bitmap;
	*access = full_access;

	read_lock(&ikvm->access_tree_lock);
	m = __kvmi_get_gfn_access(ikvm, gfn);
	if (m) {
		*access = m->access;
		*write_bitmap = m->write_bitmap;
	}
	read_unlock(&ikvm->access_tree_lock);

	return m ? 0 : -1;
}

static int kvmi_set_gfn_access(struct kvm *kvm, gfn_t gfn, u8 access,
			       u32 write_bitmap)
{
	struct kvmi_mem_access *m;
	struct kvmi_mem_access *__m;
	struct kvmi *ikvm = IKVM(kvm);
	int err = 0;
	int idx;

	m = kmem_cache_zalloc(radix_cache, GFP_KERNEL);
	if (!m)
		return -KVM_ENOMEM;

	m->gfn = gfn;
	m->access = access;
	m->write_bitmap = write_bitmap;

	/*
	 * Only try to set SPP bitmap when the page is writable.
	 * Be careful, kvm_mmu_set_subpages() will enable page write-protection
	 * by default when set SPP bitmap. If bitmap contains all 1s, it'll
	 * make the page writable by default too.
	 */
	if (!(access & KVMI_PAGE_ACCESS_W) && kvmi_spp_enabled(ikvm)) {
		struct kvm_subpage spp_info;

		spp_info.base_gfn = gfn;
		spp_info.npages = 1;
		spp_info.access_map[0] = write_bitmap;

		err = kvm_arch_set_subpages(kvm, &spp_info);
		if (err)
			goto exit;
	}

	if (radix_tree_preload(GFP_KERNEL)) {
		err = -KVM_ENOMEM;
		goto exit;
	}

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	write_lock(&ikvm->access_tree_lock);

	__m = __kvmi_get_gfn_access(ikvm, gfn);
	if (__m) {
		__m->access = access;
		__m->write_bitmap = write_bitmap;
		kvmi_arch_update_page_tracking(kvm, NULL, __m);
		if (access == full_access) {
			radix_tree_delete(&ikvm->access_tree, gfn);
			kmem_cache_free(radix_cache, __m);
		}
	} else {
		radix_tree_insert(&ikvm->access_tree, gfn, m);
		kvmi_arch_update_page_tracking(kvm, NULL, m);
		m = NULL;
	}

	write_unlock(&ikvm->access_tree_lock);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	radix_tree_preload_end();

exit:
	if (m)
		kmem_cache_free(radix_cache, m);

	return err;
}

static bool spp_access_allowed(gpa_t gpa, unsigned long bitmap)
{
	u32 off = (gpa & ~PAGE_MASK);
	u32 spp = off / 128;

	return test_bit(spp, &bitmap);
}

static bool kvmi_restricted_access(struct kvmi *ikvm, gpa_t gpa, u8 access)
{
	u32 allowed_bitmap;
	u8 allowed_access;
	int err;

	err = kvmi_get_gfn_access(ikvm, gpa_to_gfn(gpa), &allowed_access,
				  &allowed_bitmap);

	if (err)
		return false;

	/*
	 * We want to be notified only for violations involving access
	 * bits that we've specifically cleared
	 */
	if ((~allowed_access) & access) {
		bool write_access = (access & KVMI_PAGE_ACCESS_W);

		if (write_access && spp_access_allowed(gpa, allowed_bitmap))
			return false;

		return true;
	}

	return false;
}

bool is_tracked_gfn(struct kvmi *ikvm, gfn_t gfn)
{
	struct kvmi_mem_access *m;

	read_lock(&ikvm->access_tree_lock);
	m = __kvmi_get_gfn_access(ikvm, gfn);
	read_unlock(&ikvm->access_tree_lock);

	return !!m;
}

bool kvmi_tracked_gfn(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	struct kvmi *ikvm;
	bool ret;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return false;

	ret = is_tracked_gfn(ikvm, gfn);

	kvmi_put(vcpu->kvm);

	return ret;
}

static void kvmi_clear_mem_access(struct kvm *kvm)
{
	void **slot;
	struct radix_tree_iter iter;
	struct kvmi *ikvm = IKVM(kvm);
	int idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	write_lock(&ikvm->access_tree_lock);

	radix_tree_for_each_slot(slot, &ikvm->access_tree, &iter, 0) {
		struct kvmi_mem_access *m = *slot;

		m->access = full_access;
		kvmi_arch_update_page_tracking(kvm, NULL, m);

		radix_tree_iter_delete(&ikvm->access_tree, &iter, slot);
		kmem_cache_free(radix_cache, m);
	}

	write_unlock(&ikvm->access_tree_lock);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);
}

static int kvmi_control_event_breakpoint(struct kvm_vcpu *vcpu, bool enable)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvm_guest_debug dbg = {};
	int err = 0;

	if (enable) {
		if (!is_event_enabled(vcpu, KVMI_EVENT_BREAKPOINT)) {
			dbg.control = KVM_GUESTDBG_ENABLE |
				      KVM_GUESTDBG_USE_SW_BP;
			ivcpu->bp_intercepted = true;
			err = kvm_arch_vcpu_set_guest_debug(vcpu, &dbg);
		}
	} else if (is_event_enabled(vcpu, KVMI_EVENT_BREAKPOINT)) {
		ivcpu->bp_intercepted = false;
		err = kvm_arch_vcpu_set_guest_debug(vcpu, &dbg);
	}

	return err;
}

bool kvmi_bp_intercepted(struct kvm_vcpu *vcpu, u32 dbg)
{
	struct kvmi *ikvm;
	bool ret = false;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return false;

	if (IVCPU(vcpu)->bp_intercepted &&
		!(dbg & (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP))) {
		kvmi_warn_once(ikvm, "Trying to disable SW BP interception\n");
		ret = true;
	}

	kvmi_put(vcpu->kvm);

	return ret;
}
EXPORT_SYMBOL(kvmi_bp_intercepted);

static void kvmi_cache_destroy(void)
{
	kmem_cache_destroy(msg_cache);
	msg_cache = NULL;
	kmem_cache_destroy(radix_cache);
	radix_cache = NULL;
	kmem_cache_destroy(job_cache);
	job_cache = NULL;
}

static int kvmi_cache_create(void)
{
	radix_cache = kmem_cache_create("kvmi_radix_tree",
					sizeof(struct kvmi_mem_access),
					0, SLAB_ACCOUNT, NULL);
	job_cache = kmem_cache_create("kvmi_job",
				      sizeof(struct kvmi_job),
				      0, SLAB_ACCOUNT, NULL);
	msg_cache = kmem_cache_create("kvmi_msg", KVMI_MSG_SIZE_ALLOC,
				      4096, SLAB_ACCOUNT, NULL);

	if (!msg_cache || !radix_cache || !job_cache) {
		kvmi_cache_destroy();

		return -1;
	}

	return 0;
}

int kvmi_init(void)
{
	kvmi_mem_init();
	return kvmi_cache_create();
}

void kvmi_uninit(void)
{
	kvmi_mem_exit();
	kvmi_cache_destroy();
}

static bool alloc_kvmi(struct kvm *kvm, const struct kvm_introspection *qemu)
{
	struct kvmi *ikvm;

	ikvm = kzalloc(sizeof(*ikvm), GFP_KERNEL);
	if (!ikvm)
		return false;

	/* see comments of radix_tree_preload() - no direct reclaim */
	INIT_RADIX_TREE(&ikvm->access_tree, GFP_KERNEL & ~__GFP_DIRECT_RECLAIM);
	rwlock_init(&ikvm->access_tree_lock);

	atomic_set(&ikvm->ev_seq, 0);

	set_bit(KVMI_GET_VERSION, ikvm->cmd_allow_mask);
	set_bit(KVMI_CHECK_COMMAND, ikvm->cmd_allow_mask);
	set_bit(KVMI_CHECK_EVENT, ikvm->cmd_allow_mask);

	memcpy(&ikvm->uuid, &qemu->uuid, sizeof(ikvm->uuid));

	ikvm->kptn_node.track_preread = kvmi_track_preread;
	ikvm->kptn_node.track_prewrite = kvmi_track_prewrite;
	ikvm->kptn_node.track_preexec = kvmi_track_preexec;
	ikvm->kptn_node.track_create_slot = kvmi_track_create_slot;
	ikvm->kptn_node.track_flush_slot = kvmi_track_flush_slot;

	ikvm->kvm = kvm;
	kvm->kvmi = ikvm;

	return true;
}

static int __kvmi_add_job(struct kvm_vcpu *vcpu,
			  void (*fct)(struct kvm_vcpu *vcpu, void *ctx),
			  void *ctx, void (*free_fct)(void *ctx))
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvmi_job *job;

	job = kmem_cache_zalloc(job_cache, GFP_KERNEL);
	if (unlikely(!job))
		return -ENOMEM;

	INIT_LIST_HEAD(&job->link);
	job->fct = fct;
	job->ctx = ctx;
	job->free_fct = free_fct;

	spin_lock(&ivcpu->job_lock);
	list_add_tail(&job->link, &ivcpu->job_list);
	spin_unlock(&ivcpu->job_lock);

	return 0;
}

int kvmi_add_job(struct kvm_vcpu *vcpu,
		 void (*fct)(struct kvm_vcpu *vcpu, void *ctx),
		 void *ctx, void (*free_fct)(void *ctx))
{
	int err;

	err = __kvmi_add_job(vcpu, fct, ctx, free_fct);

	if (!err) {
		kvm_make_request(KVM_REQ_INTROSPECTION, vcpu);
		kvm_vcpu_kick(vcpu);
	}

	return err;
}

static void kvmi_free_job(struct kvmi_job *job)
{
	if (job->free_fct)
		job->free_fct(job->ctx);

	kmem_cache_free(job_cache, job);
}

static struct kvmi_job *kvmi_pull_job(struct kvmi_vcpu *ivcpu)
{
	struct kvmi_job *job = NULL;

	spin_lock(&ivcpu->job_lock);
	job = list_first_entry_or_null(&ivcpu->job_list, typeof(*job), link);
	if (job)
		list_del(&job->link);
	spin_unlock(&ivcpu->job_lock);

	return job;
}

static void kvmi_job_create_vcpu(struct kvm_vcpu *vcpu, void *ctx)
{
	kvmi_create_vcpu_event(vcpu);
}

static bool alloc_ivcpu(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu;

	ivcpu = kzalloc(sizeof(*ivcpu), GFP_KERNEL);
	if (!ivcpu)
		return false;

	INIT_LIST_HEAD(&ivcpu->job_list);
	spin_lock_init(&ivcpu->job_lock);

	vcpu->kvmi = ivcpu;

	return true;
}

struct kvmi * __must_check kvmi_get(struct kvm *kvm)
{
	if (refcount_inc_not_zero(&kvm->kvmi_ref))
		return kvm->kvmi;

	return NULL;
}

static void kvmi_clear_vcpu_jobs(struct kvm *kvm)
{
	int i;
	struct kvm_vcpu *vcpu;
	struct kvmi_job *cur, *next;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

		if (!ivcpu)
			continue;

		spin_lock(&ivcpu->job_lock);
		list_for_each_entry_safe(cur, next, &ivcpu->job_list, link) {
			list_del(&cur->link);
			kvmi_free_job(cur);
		}
		spin_unlock(&ivcpu->job_lock);
	}
}

static void kvmi_destroy(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	int i;

	kfree(kvm->kvmi);
	kvm->kvmi = NULL;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		kfree(vcpu->kvmi);
		vcpu->kvmi = NULL;
	}
}

static void kvmi_release(struct kvm *kvm)
{
	kvmi_sock_put(IKVM(kvm));
	kvmi_clear_vcpu_jobs(kvm);
	kvmi_destroy(kvm);

	complete(&kvm->kvmi_completed);
}

/* This function may be called from atomic context and must not sleep */
void kvmi_put(struct kvm *kvm)
{
	if (refcount_dec_and_test(&kvm->kvmi_ref))
		kvmi_release(kvm);
}

/*
 * VCPU hotplug - this function will likely be called before VCPU will start
 * executing code
 */
int kvmi_vcpu_init(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm;
	int ret = 0;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return 0;

	if (!alloc_ivcpu(vcpu)) {
		kvmi_err(ikvm, "Unable to alloc ivcpu for vcpu_id %u\n",
			 vcpu->vcpu_id);
		ret = -ENOMEM;
		goto out;
	}

	if (kvmi_add_job(vcpu, kvmi_job_create_vcpu, NULL, NULL))
		ret = -ENOMEM;

out:
	kvmi_put(vcpu->kvm);

	return ret;
}

/*
 * VCPU hotplug - this function will likely be called after VCPU will stop
 * executing code
 */
void kvmi_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	/*
	 * Under certain circumstances (errors in creating the VCPU, hotplug?)
	 * this function may be reached with the KVMI member still allocated.
	 * This VCPU won't be reachable by the introspection engine, so no
	 * protection is necessary when de-allocating.
	 */
	kfree(vcpu->kvmi);
	vcpu->kvmi = NULL;
}

static bool is_pf_of_interest(struct kvm_vcpu *vcpu, gpa_t gpa, u8 access)
{
	struct kvm *kvm = vcpu->kvm;

	if (kvm_mmu_nested_pagefault(vcpu))
		return false;

	/* Have we shown interest in this page? */
	return kvmi_restricted_access(IKVM(kvm), gpa, access);
}

/*
 * The custom input is defined by a virtual address and size, and all reads
 * must be within this space. Reads that are completely outside should be
 * satisfyied using guest memory. Overlapping reads are erroneous.
 */
static int use_custom_input(struct kvm_vcpu *vcpu, gva_t gva, u8 *new,
			    int bytes)
{
	unsigned int offset;
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

	if (!ivcpu->ctx_size || !bytes)
		return 0;

	if (bytes < 0 || bytes > ivcpu->ctx_size) {
		kvmi_warn_once(IKVM(vcpu->kvm),
			       "invalid range: %d (max: %u)\n",
			       bytes, ivcpu->ctx_size);
		return 0;
	}

	if (gva + bytes <= ivcpu->ctx_addr ||
	    gva >= ivcpu->ctx_addr + ivcpu->ctx_size)
		return 0;

	if (gva < ivcpu->ctx_addr && gva + bytes > ivcpu->ctx_addr) {
		kvmi_warn_once(IKVM(vcpu->kvm),
			       "read ranges overlap: 0x%lx:%d, 0x%llx:%u\n",
			       gva, bytes, ivcpu->ctx_addr, ivcpu->ctx_size);
		return 0;
	}

	if (gva + bytes > ivcpu->ctx_addr + ivcpu->ctx_size) {
		kvmi_warn_once(IKVM(vcpu->kvm),
			       "read ranges overlap: 0x%lx:%d, 0x%llx:%u\n",
			       gva, bytes, ivcpu->ctx_addr, ivcpu->ctx_size);
		return 0;
	}

	offset = gva - ivcpu->ctx_addr;

	memcpy(new, ivcpu->ctx_data + offset, bytes);

	return bytes;
}

static bool __kvmi_track_preread(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
	u8 *new, int bytes, struct kvm_page_track_notifier_node *node,
	bool *data_ready)
{
	bool ret;

	if (!is_pf_of_interest(vcpu, gpa, KVMI_PAGE_ACCESS_R))
		return true;

	if (use_custom_input(vcpu, gva, new, bytes))
		goto out_custom;

	ret = kvmi_arch_pf_event(vcpu, gpa, gva, KVMI_PAGE_ACCESS_R);

	if (ret && use_custom_input(vcpu, gva, new, bytes))
		goto out_custom;

	return ret;

out_custom:
	if (*data_ready)
		kvmi_err(IKVM(vcpu->kvm),
			"Override custom data from another tracker\n");

	*data_ready = true;

	return true;
}

static bool kvmi_track_preread(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
	u8 *new, int bytes, struct kvm_page_track_notifier_node *node,
	bool *data_ready)
{
	struct kvmi *ikvm;
	bool ret = true;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return true;

	if (is_event_enabled(vcpu, KVMI_EVENT_PF))
		ret = __kvmi_track_preread(vcpu, gpa, gva, new, bytes, node,
					   data_ready);

	kvmi_put(vcpu->kvm);

	return ret;
}

static bool __kvmi_track_prewrite(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
	const u8 *new, int bytes,
	struct kvm_page_track_notifier_node *node)
{
	if (!is_pf_of_interest(vcpu, gpa, KVMI_PAGE_ACCESS_W))
		return true;

	return kvmi_arch_pf_event(vcpu, gpa, gva, KVMI_PAGE_ACCESS_W);
}

static bool kvmi_track_prewrite(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
	const u8 *new, int bytes,
	struct kvm_page_track_notifier_node *node)
{
	struct kvmi *ikvm;
	bool ret = true;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return true;

	if (is_event_enabled(vcpu, KVMI_EVENT_PF))
		ret = __kvmi_track_prewrite(vcpu, gpa, gva, new, bytes, node);

	kvmi_put(vcpu->kvm);

	return ret;
}

static bool __kvmi_track_preexec(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
	struct kvm_page_track_notifier_node *node)
{
	if (!is_pf_of_interest(vcpu, gpa, KVMI_PAGE_ACCESS_X))
		return true;

	return kvmi_arch_pf_event(vcpu, gpa, gva, KVMI_PAGE_ACCESS_X);
}

static bool kvmi_track_preexec(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
	struct kvm_page_track_notifier_node *node)
{
	struct kvmi *ikvm;
	bool ret = true;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return true;

	if (is_event_enabled(vcpu, KVMI_EVENT_PF))
		ret = __kvmi_track_preexec(vcpu, gpa, gva, node);

	kvmi_put(vcpu->kvm);

	return ret;
}

static void kvmi_track_create_slot(struct kvm *kvm,
	struct kvm_memory_slot *slot,
	unsigned long npages,
	struct kvm_page_track_notifier_node *node)
{
	struct kvmi *ikvm;
	gfn_t start = slot->base_gfn;
	const gfn_t end = start + npages;
	int idx;

	ikvm = kvmi_get(kvm);
	if (!ikvm)
		return;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	read_lock(&ikvm->access_tree_lock);

	while (start < end) {
		struct kvmi_mem_access *m;

		m = __kvmi_get_gfn_access(ikvm, start);
		if (m)
			kvmi_arch_update_page_tracking(kvm, slot, m);
		start++;
	}

	read_unlock(&ikvm->access_tree_lock);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	kvmi_put(kvm);
}

static void kvmi_track_flush_slot(struct kvm *kvm, struct kvm_memory_slot *slot,
	struct kvm_page_track_notifier_node *node)
{
	struct kvmi *ikvm;
	gfn_t start = slot->base_gfn;
	const gfn_t end = start + slot->npages;
	int idx;

	ikvm = kvmi_get(kvm);
	if (!ikvm)
		return;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	write_lock(&ikvm->access_tree_lock);

	while (start < end) {
		struct kvmi_mem_access *m;

		m = __kvmi_get_gfn_access(ikvm, start);
		if (m) {
			u8 prev_access = m->access;

			m->access = full_access;
			kvmi_arch_update_page_tracking(kvm, slot, m);
			m->access = prev_access;
		}

		start++;
	}

	write_unlock(&ikvm->access_tree_lock);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	kvmi_put(kvm);
}

static void kvmi_end_introspection(struct kvmi *ikvm)
{
	struct kvm *kvm = ikvm->kvm;

	/* Signal QEMU which is waiting for POLLHUP. */
	kvmi_sock_shutdown(ikvm);

	/*
	 * Trigger all the VCPUs out of waiting for replies. Although the
	 * introspection is still enabled, sending additional events will
	 * fail because the socket is shut down. Waiting will not be possible.
	 */
	kvmi_abort_events(kvm);

	/*
	 * This may sleep on synchronize_srcu() so it's not allowed to be
	 * called under kvmi_put().
	 * Also synchronize_srcu() may deadlock on (page tracking) read-side
	 * regions that are waiting for reply to events, so must be called
	 * after kvmi_abort_events().
	 */
	kvm_page_track_unregister_notifier(kvm, &ikvm->kptn_node);

	/*
	 * This function uses kvm->mmu_lock so it's not allowed to be
	 * called under kvmi_put(). It can reach a deadlock if called
	 * from kvm_mmu_load -> kvmi_tracked_gfn -> kvmi_put.
	 */
	kvmi_clear_mem_access(kvm);

	/*
	 * At this moment the socket is shut down, no more commands will come
	 * from the introspector, and the only way into the introspection is
	 * thru the event handlers. Make sure the introspection ends.
	 */
	kvmi_put(kvm);
}

static int kvmi_recv(void *arg)
{
	struct kvmi *ikvm = arg;

	kvmi_info(ikvm, "Hooking VM\n");

	while (kvmi_msg_process(ikvm))
		;

	kvmi_info(ikvm, "Unhooking VM\n");

	kvmi_end_introspection(ikvm);

	return 0;
}

int kvmi_hook(struct kvm *kvm, const struct kvm_introspection *qemu)
{
	struct kvm_vcpu *vcpu;
	struct kvmi *ikvm;
	int i, err = 0;

	/* wait for the previous introspection to finish */
	err = wait_for_completion_killable(&kvm->kvmi_completed);
	if (err)
		return err;

	/* ensure no VCPU hotplug happens until we set the reference */
	mutex_lock(&kvm->lock);

	if (!alloc_kvmi(kvm, qemu)) {
		mutex_unlock(&kvm->lock);
		return -ENOMEM;
	}
	ikvm = IKVM(kvm);

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (!alloc_ivcpu(vcpu)) {
			err = -ENOMEM;
			goto err_alloc;
		}
		if (kvmi_add_job(vcpu, kvmi_job_create_vcpu, NULL, NULL)) {
			err = -ENOMEM;
			goto err_alloc;
		}
	}

	/* interact with other kernel components after structure allocation */
	if (!kvmi_sock_get(ikvm, qemu->fd)) {
		err = -EINVAL;
		goto err_alloc;
	}

	kvm_page_track_register_notifier(kvm, &ikvm->kptn_node);

	/*
	 * Make sure all the KVM/KVMI structures are linked and no pointer
	 * is read as NULL after the reference count has been set.
	 */
	smp_mb__before_atomic();
	refcount_set(&kvm->kvmi_ref, 1);

	mutex_unlock(&kvm->lock);

	ikvm->recv = kthread_run(kvmi_recv, ikvm, "kvmi-recv");
	if (IS_ERR(ikvm->recv)) {
		kvmi_err(ikvm, "Unable to create receiver thread!\n");
		err = PTR_ERR(ikvm->recv);
		goto err_recv;
	}

	return 0;

err_recv:
	/*
	 * introspection has oficially started since reference count has been
	 * set (and some event handlers may have already acquired it), but
	 * without the receiver thread; we must emulate its shutdown behavior
	 */
	kvmi_end_introspection(ikvm);

	return err;

err_alloc:
	kvmi_release(kvm);

	mutex_unlock(&kvm->lock);

	return err;
}

int kvmi_ioctl_hook(struct kvm *kvm, void __user *argp)
{
	struct kvm_introspection i;

	if (copy_from_user(&i, argp, sizeof(i)))
		return -EFAULT;

	if (i.padding)
		return -EINVAL;

	return kvmi_hook(kvm, &i);
}

static int kvmi_ioctl_get_feature(void __user *argp, bool *allow, int *id,
				  unsigned long *bitmask)
{
	struct kvm_introspection_feature feat;
	int all_bits = -1;

	if (copy_from_user(&feat, argp, sizeof(feat)))
		return -EFAULT;

	if (feat.id < 0 && feat.id != all_bits)
		return -EINVAL;

	*allow = !!(feat.allow & 1);
	*id = feat.id;
	*bitmask = *id == all_bits ? -1 : BIT(feat.id);

	return 0;
}

static int kvmi_ioctl_feature(struct kvm *kvm,
			      bool allow, unsigned long *requested,
			      size_t off_dest, unsigned int nbits)
{
	unsigned long *dest;
	struct kvmi *ikvm;

	if (bitmap_empty(requested, nbits))
		return -EINVAL;

	ikvm = kvmi_get(kvm);
	if (!ikvm)
		return -EFAULT;

	dest = (unsigned long *)((char *)ikvm + off_dest);

	if (allow)
		bitmap_or(dest, dest, requested, nbits);
	else
		bitmap_andnot(dest, dest, requested, nbits);

	kvmi_put(kvm);

	return 0;
}

int kvmi_ioctl_event(struct kvm *kvm, void __user *argp)
{
	DECLARE_BITMAP(requested, KVMI_NUM_EVENTS);
	DECLARE_BITMAP(known, KVMI_NUM_EVENTS);
	bool allow;
	int err;
	int id;

	err = kvmi_ioctl_get_feature(argp, &allow, &id, requested);
	if (err)
		return err;

	bitmap_from_u64(known, KVMI_KNOWN_EVENTS);
	bitmap_and(requested, requested, known, KVMI_NUM_EVENTS);

	return kvmi_ioctl_feature(kvm, allow, requested,
				  offsetof(struct kvmi, event_allow_mask),
				  KVMI_NUM_EVENTS);
}

int kvmi_ioctl_command(struct kvm *kvm, void __user *argp)
{
	DECLARE_BITMAP(requested, KVMI_NUM_COMMANDS);
	DECLARE_BITMAP(known, KVMI_NUM_COMMANDS);
	bool allow;
	int err;
	int id;

	err = kvmi_ioctl_get_feature(argp, &allow, &id, requested);
	if (err)
		return err;

	bitmap_from_u64(known, KVMI_KNOWN_COMMANDS);
	bitmap_and(requested, requested, known, KVMI_NUM_COMMANDS);

	if (!allow) {
		DECLARE_BITMAP(always_allowed, KVMI_NUM_COMMANDS);

		if (id == KVMI_GET_VERSION
				|| id == KVMI_CHECK_COMMAND
				|| id == KVMI_CHECK_EVENT)
			return -EPERM;

		set_bit(KVMI_GET_VERSION, always_allowed);
		set_bit(KVMI_CHECK_COMMAND, always_allowed);
		set_bit(KVMI_CHECK_EVENT, always_allowed);

		bitmap_andnot(requested, requested, always_allowed,
			      KVMI_NUM_COMMANDS);
	}

	return kvmi_ioctl_feature(kvm, allow, requested,
				  offsetof(struct kvmi, cmd_allow_mask),
				  KVMI_NUM_COMMANDS);
}

void kvmi_create_vm(struct kvm *kvm)
{
	init_completion(&kvm->kvmi_completed);
	complete(&kvm->kvmi_completed);
}

void kvmi_destroy_vm(struct kvm *kvm)
{
	struct kvmi *ikvm;

	ikvm = kvmi_get(kvm);
	if (!ikvm)
		return;

	/* trigger socket shutdown - kvmi_recv() will start shutdown process */
	kvmi_sock_shutdown(ikvm);

	kvmi_put(kvm);

	/* wait for introspection resources to be released */
	wait_for_completion_killable(&kvm->kvmi_completed);
}

static u8 kvmi_translate_pf_error_code(u64 error_code)
{
	u8 access = 0;

	if (error_code & PFERR_USER_MASK)
		access |= KVMI_PAGE_ACCESS_R;
	if (error_code & PFERR_WRITE_MASK)
		access |= KVMI_PAGE_ACCESS_W;
	if (error_code & PFERR_FETCH_MASK)
		access |= KVMI_PAGE_ACCESS_X;

	return access;
}

static bool __kvmi_single_step(struct kvm_vcpu *vcpu, gpa_t gpa,
			       int *emulation_type)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvmi *ikvm = IKVM(kvm);
	u8 allowed_access, pf_access;
	u32 ignored_write_bitmap;
	gfn_t gfn = gpa_to_gfn(gpa);
	int err;

	if (is_ud2_instruction(vcpu, emulation_type))
		return false;

	err = kvmi_get_gfn_access(ikvm, gfn, &allowed_access,
				  &ignored_write_bitmap);
	if (err) {
		kvmi_warn(ikvm, "%s: gfn 0x%llx not found in the radix tree\n",
			  __func__, gpa_to_gfn(gpa));
		return false;
	}

	pf_access = kvmi_translate_pf_error_code(vcpu->arch.error_code);

	return kvmi_start_ss(vcpu, gpa, pf_access);
}

bool kvmi_single_step(struct kvm_vcpu *vcpu, gpa_t gpa, int *emulation_type)
{
	struct kvmi *ikvm;
	bool ret = false;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return false;

	ret = __kvmi_single_step(vcpu, gpa, emulation_type);

	kvmi_put(vcpu->kvm);

	return ret;
}

static int kvmi_vcpu_kill(int sig, struct kvm_vcpu *vcpu)
{
	int err = -ESRCH;
	struct pid *pid;
	struct kernel_siginfo siginfo[1] = {};

	rcu_read_lock();
	pid = rcu_dereference(vcpu->pid);
	if (pid)
		err = kill_pid_info(sig, siginfo, pid);
	rcu_read_unlock();

	return err;
}

static void kvmi_vm_shutdown(struct kvm *kvm)
{
	int i;
	struct kvm_vcpu *vcpu;

	kvm_for_each_vcpu(i, vcpu, kvm)
		kvmi_vcpu_kill(SIGTERM, vcpu);
}

void kvmi_handle_common_event_actions(struct kvm_vcpu *vcpu, u32 action,
				      const char *str)
{
	struct kvm *kvm = vcpu->kvm;

	switch (action) {
	case KVMI_EVENT_ACTION_CRASH:
		kvmi_vm_shutdown(kvm);
		break;

	default:
		kvmi_err(IKVM(kvm), "Unsupported action %d for event %s\n",
			 action, str);
	}
}

void kvmi_init_emulate(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm;
	struct kvmi_vcpu *ivcpu;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return;

	ivcpu = IVCPU(vcpu);

	ivcpu->rep_complete = false;
	ivcpu->effective_rep_complete = false;

	ivcpu->ctx_size = 0;
	ivcpu->ctx_addr = 0;

	kvmi_put(vcpu->kvm);
}
EXPORT_SYMBOL(kvmi_init_emulate);

/*
 * If the user has requested that events triggered by repetitive
 * instructions be suppressed after the first cycle, then this
 * function will effectively activate it. This ensures that we don't
 * prematurely suppress potential events (second or later) triggerd
 * by an instruction during a single pass.
 */
void kvmi_activate_rep_complete(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return;

	IVCPU(vcpu)->effective_rep_complete = IVCPU(vcpu)->rep_complete;

	kvmi_put(vcpu->kvm);
}
EXPORT_SYMBOL(kvmi_activate_rep_complete);

bool kvmi_breakpoint_event(struct kvm_vcpu *vcpu, u64 gva, u8 insn_len)
{
	struct kvmi *ikvm;
	bool ret = false;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return true;

	if (is_event_enabled(vcpu, KVMI_EVENT_BREAKPOINT))
		kvmi_arch_breakpoint_event(vcpu, gva, insn_len);
	else
		ret = true;

	kvmi_put(vcpu->kvm);

	return ret;
}
EXPORT_SYMBOL(kvmi_breakpoint_event);

bool kvmi_hypercall_event(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm;
	bool ret = false;

	if (!kvmi_arch_is_agent_hypercall(vcpu))
		return ret;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return ret;

	if (is_event_enabled(vcpu, KVMI_EVENT_HYPERCALL)) {
		kvmi_arch_hypercall_event(vcpu);
		ret = true;
	}

	kvmi_put(vcpu->kvm);

	return ret;
}

/*
 * This function returns false if there is an exception or interrupt pending.
 * It returns true in all other cases including KVMI not being initialized.
 */
bool kvmi_queue_exception(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm;
	bool ret = true;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return true;

	if (!IVCPU(vcpu)->exception.pending)
		goto out;

	ret = kvmi_arch_queue_exception(vcpu);

	memset(&IVCPU(vcpu)->exception, 0, sizeof(IVCPU(vcpu)->exception));

out:
	kvmi_put(vcpu->kvm);

	return ret;
}

void kvmi_trap_event(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return;

	if (is_event_enabled(vcpu, KVMI_EVENT_TRAP))
		kvmi_arch_trap_event(vcpu);

	kvmi_put(vcpu->kvm);
}

static u32 kvmi_send_singlestep(struct kvm_vcpu *vcpu)
{
	int err, action;

	err = kvmi_send_event(vcpu, KVMI_EVENT_SINGLESTEP, NULL, 0,
			      NULL, 0, &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	return action;
}

static void __kvmi_singlestep_event(struct kvm_vcpu *vcpu)
{
	u32 action;

	trace_kvmi_event_singlestep_send(vcpu->vcpu_id);

	action = kvmi_send_singlestep(vcpu);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		break;
	default:
		kvmi_handle_common_event_actions(vcpu, action, "SINGLESTEP");
	}

	trace_kvmi_event_singlestep_recv(vcpu->vcpu_id, action);
}

static void kvmi_singlestep_event(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

	if (!ivcpu->ss_requested)
		return;

	if (is_event_enabled(vcpu, KVMI_EVENT_SINGLESTEP))
		__kvmi_singlestep_event(vcpu);

	ivcpu->ss_requested = false;
}

static bool __kvmi_create_vcpu_event(struct kvm_vcpu *vcpu)
{
	u32 action;
	bool ret = false;

	trace_kvmi_event_create_vcpu_send(vcpu->vcpu_id);

	action = kvmi_msg_send_create_vcpu(vcpu);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		ret = true;
		break;
	default:
		kvmi_handle_common_event_actions(vcpu, action, "CREATE");
	}

	trace_kvmi_event_create_vcpu_recv(vcpu->vcpu_id, action);

	return ret;
}

static bool kvmi_create_vcpu_event(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm;
	bool ret = true;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return true;

	if (test_bit(KVMI_EVENT_CREATE_VCPU, ikvm->vm_ev_mask))
		ret = __kvmi_create_vcpu_event(vcpu);

	kvmi_put(vcpu->kvm);

	return ret;
}

static bool __kvmi_pause_vcpu_event(struct kvm_vcpu *vcpu)
{
	u32 action;
	bool ret = false;

	trace_kvmi_event_pause_vcpu_send(vcpu->vcpu_id);

	action = kvmi_msg_send_pause_vcpu(vcpu);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		ret = true;
		break;
	default:
		kvmi_handle_common_event_actions(vcpu, action, "PAUSE");
	}

	trace_kvmi_event_pause_vcpu_recv(vcpu->vcpu_id, action);

	return ret;
}

static bool kvmi_pause_vcpu_event(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm;
	bool ret = true;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return true;

	ret = __kvmi_pause_vcpu_event(vcpu);

	kvmi_put(vcpu->kvm);

	return ret;
}

void kvmi_run_jobs(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvmi_job *job;

	while ((job = kvmi_pull_job(ivcpu))) {
		job->fct(vcpu, job->ctx);
		kvmi_free_job(job);
	}
}

static bool need_to_wait_for_ss(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvmi *ikvm = IKVM(vcpu->kvm);

	return atomic_read(&ikvm->ss_active) && !ivcpu->ss_owner;
}

static bool need_to_wait(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

	return ivcpu->reply_waiting || need_to_wait_for_ss(vcpu);
}

static bool done_waiting(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

	if (!need_to_wait(vcpu))
		return true;

	return !list_empty(&ivcpu->job_list);
}

static void kvmi_job_wait(struct kvm_vcpu *vcpu, void *ctx)
{
	struct swait_queue_head *wq = kvm_arch_vcpu_wq(vcpu);
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	int err;

	err = swait_event_killable(*wq, done_waiting(vcpu));

	if (err)
		ivcpu->killed = true;
}

int kvmi_run_jobs_and_wait(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	int err = 0;

	for (;;) {
		kvmi_run_jobs(vcpu);

		if (ivcpu->killed) {
			err = -1;
			break;
		}

		if (!need_to_wait(vcpu))
			break;

		kvmi_add_job(vcpu, kvmi_job_wait, NULL, NULL);
	}

	return err;
}

void kvmi_handle_requests(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvmi *ikvm;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return;

	for (;;) {
		int err = kvmi_run_jobs_and_wait(vcpu);

		if (err)
			break;

		if (!atomic_read(&ivcpu->pause_requests))
			break;

		atomic_dec(&ivcpu->pause_requests);
		kvmi_pause_vcpu_event(vcpu);
	}

	kvmi_put(vcpu->kvm);
}

void kvmi_post_reply(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

	if (ivcpu->have_delayed_regs) {
		kvm_arch_vcpu_set_regs(vcpu, &ivcpu->delayed_regs);
		ivcpu->have_delayed_regs = false;
	}
}

int kvmi_cmd_set_registers(struct kvm_vcpu *vcpu, const struct kvm_regs *regs)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

	if (ivcpu->reply_waiting) {
		/* defer set registers until we get the reply */
		memcpy(&ivcpu->delayed_regs, regs, sizeof(ivcpu->delayed_regs));
		ivcpu->have_delayed_regs = true;
	} else {
		kvmi_err(IKVM(vcpu->kvm), "Dropped KVMI_SET_REGISTERS\n");
	}

	return 0;
}

int kvmi_cmd_get_page_access(struct kvmi *ikvm, u64 gpa, u8 *access)
{
	gfn_t gfn = gpa_to_gfn(gpa);
	u32 ignored_write_bitmap;

	kvmi_get_gfn_access(ikvm, gfn, access, &ignored_write_bitmap);

	return 0;
}

int kvmi_cmd_get_page_write_bitmap(struct kvmi *ikvm, u64 gpa,
				   u32 *write_bitmap)
{
	gfn_t gfn = gpa_to_gfn(gpa);
	u8 ignored_access;

	kvmi_get_gfn_access(ikvm, gfn, &ignored_access, write_bitmap);

	return 0;
}

int kvmi_cmd_set_page_access(struct kvmi *ikvm, u64 gpa, u8 access)
{
	gfn_t gfn = gpa_to_gfn(gpa);
	u8 ignored_access;
	u32 write_bitmap;

	kvmi_get_gfn_access(ikvm, gfn, &ignored_access, &write_bitmap);

	return kvmi_set_gfn_access(ikvm->kvm, gfn, access, write_bitmap);
}

int kvmi_cmd_set_page_write_bitmap(struct kvmi *ikvm, u64 gpa,
				   u32 write_bitmap)
{
	bool write_allowed_for_all;
	gfn_t gfn = gpa_to_gfn(gpa);
	u32 ignored_write_bitmap;
	u8 access;

	kvmi_get_gfn_access(ikvm, gfn, &access, &ignored_write_bitmap);

	write_allowed_for_all = (write_bitmap == (u32)((1ULL << 32) - 1));
	if (write_allowed_for_all)
		access |= KVMI_PAGE_ACCESS_W;
	else
		access &= ~KVMI_PAGE_ACCESS_W;

	return kvmi_set_gfn_access(ikvm->kvm, gfn, access, write_bitmap);
}

unsigned long gfn_to_hva_safe(struct kvm *kvm, gfn_t gfn)
{
	unsigned long hva;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&kvm->srcu);
	hva = gfn_to_hva(kvm, gfn);
	srcu_read_unlock(&kvm->srcu, srcu_idx);

	return hva;
}

static long get_user_pages_remote_unlocked(struct mm_struct *mm,
	unsigned long start,
	unsigned long nr_pages,
	unsigned int gup_flags,
	struct page **pages)
{
	long ret;
	struct task_struct *tsk = NULL;
	struct vm_area_struct **vmas = NULL;
	int locked = 1;

	down_read(&mm->mmap_sem);
	ret = get_user_pages_remote(tsk, mm, start, nr_pages, gup_flags,
		pages, vmas, &locked);
	if (locked)
		up_read(&mm->mmap_sem);
	return ret;
}

static void *get_page_ptr(struct kvm *kvm, gpa_t gpa, struct page **page,
			  bool write)
{
	unsigned int flags = write ? FOLL_WRITE : 0;
	unsigned long hva;

	*page = NULL;

	hva = gfn_to_hva_safe(kvm, gpa_to_gfn(gpa));

	if (kvm_is_error_hva(hva)) {
		kvmi_err(IKVM(kvm), "Invalid gpa %llx\n", gpa);
		return NULL;
	}

	if (get_user_pages_remote_unlocked(kvm->mm, hva, 1, flags, page) != 1) {
		kvmi_err(IKVM(kvm),
			 "Failed to get the page for hva %lx gpa %llx\n",
			 hva, gpa);
		return NULL;
	}

	return kmap_atomic(*page);
}

static void put_page_ptr(void *ptr, struct page *page)
{
	if (ptr)
		kunmap_atomic(ptr);
	if (page)
		put_page(page);
}

int kvmi_cmd_read_physical(struct kvm *kvm, u64 gpa, u64 size, int(*send)(
	struct kvmi *, const struct kvmi_msg_hdr *,
	int err, const void *buf, size_t),
	const struct kvmi_msg_hdr *ctx)
{
	int err, ec = 0;
	struct page *page = NULL;
	void *ptr_page = NULL, *ptr = NULL;
	size_t ptr_size = 0;

	ptr_page = get_page_ptr(kvm, gpa, &page, false);
	if (!ptr_page) {
		ec = -KVM_ENOENT;
		goto out;
	}

	ptr = ptr_page + (gpa & ~PAGE_MASK);
	ptr_size = size;

out:
	err = send(IKVM(kvm), ctx, ec, ptr, ptr_size);

	put_page_ptr(ptr_page, page);
	return err;
}

int kvmi_cmd_write_physical(struct kvm *kvm, u64 gpa, u64 size, const void *buf)
{
	struct page *page;
	void *ptr;

	ptr = get_page_ptr(kvm, gpa, &page, true);
	if (!ptr)
		return -KVM_ENOENT;

	memcpy(ptr + (gpa & ~PAGE_MASK), buf, size);

	put_page_ptr(ptr, page);

	return 0;
}

int kvmi_cmd_alloc_token(struct kvm *kvm, struct kvmi_map_mem_token *token)
{
	return kvmi_mem_generate_token(kvm, token);
}

int kvmi_cmd_get_max_gfn(struct kvm *kvm, gfn_t *gfn)
{
	return kvm_get_max_gfn(kvm, gfn);
}

int kvmi_cmd_control_events(struct kvm_vcpu *vcpu, unsigned int event_id,
			    bool enable)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	int err;

	switch (event_id) {
	case KVMI_EVENT_BREAKPOINT:
		err = kvmi_control_event_breakpoint(vcpu, enable);
		break;
	default:
		err = kvmi_arch_cmd_control_event(vcpu, event_id, enable);
		break;
	}

	if (!err) {
		if (enable)
			set_bit(event_id, ivcpu->ev_mask);
		else
			clear_bit(event_id, ivcpu->ev_mask);
	}

	return err;
}

int kvmi_cmd_control_vm_events(struct kvmi *ikvm, unsigned int event_id,
			       bool enable)
{
	if (enable)
		set_bit(event_id, ikvm->vm_ev_mask);
	else
		clear_bit(event_id, ikvm->vm_ev_mask);

	return 0;
}

int kvmi_cmd_pause_vcpu(struct kvm_vcpu *vcpu, bool wait)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	unsigned int req = KVM_REQ_INTROSPECTION;

	if (atomic_read(&ivcpu->pause_requests) > MAX_PAUSE_REQUESTS)
		return -KVM_EBUSY;

	atomic_inc(&ivcpu->pause_requests);
	kvm_make_request(req, vcpu);
	if (wait)
		kvm_vcpu_kick_and_wait(vcpu);
	else
		kvm_vcpu_kick(vcpu);

	return 0;
}

static int write_custom_data_to_page(struct kvm_vcpu *vcpu, gva_t gva,
					u8 *backup, size_t bytes)
{
	u8 *ptr_page, *ptr;
	struct page *page;
	gpa_t gpa;

	gpa = kvm_mmu_gva_to_gpa_system(vcpu, gva, 0, NULL);
	if (gpa == UNMAPPED_GVA)
		return -KVM_EINVAL;

	ptr_page = get_page_ptr(vcpu->kvm, gpa, &page, true);
	if (!ptr_page)
		return -KVM_EINVAL;

	ptr = ptr_page + (gpa & ~PAGE_MASK);

	memcpy(backup, ptr, bytes);
	use_custom_input(vcpu, gva, ptr, bytes);

	put_page_ptr(ptr_page, page);

	return 0;
}

static int write_custom_data(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm = IKVM(vcpu->kvm);
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	size_t bytes = ivcpu->ctx_size;
	gva_t gva = ivcpu->ctx_addr;
	u8 *backup;

	if (ikvm->ss_custom_size)
		return 0;

	if (!bytes)
		return 0;

	backup = ikvm->ss_custom_data;

	while (bytes) {
		size_t offset = gva & ~PAGE_MASK;
		size_t chunk = min(bytes, PAGE_SIZE - offset);

		if (write_custom_data_to_page(vcpu, gva, backup, chunk))
			return -KVM_EINVAL;

		bytes -= chunk;
		backup += chunk;
		gva += chunk;
		ikvm->ss_custom_size += chunk;
	}

	return 0;
}

static int restore_backup_data_to_page(struct kvm_vcpu *vcpu, gva_t gva,
					u8 *src, size_t bytes)
{
	u8 *ptr_page, *ptr;
	struct page *page;
	gpa_t gpa;

	gpa = kvm_mmu_gva_to_gpa_system(vcpu, gva, 0, NULL);
	if (gpa == UNMAPPED_GVA)
		return -KVM_EINVAL;

	ptr_page = get_page_ptr(vcpu->kvm, gpa, &page, true);
	if (!ptr_page)
		return -KVM_EINVAL;

	ptr = ptr_page + (gpa & ~PAGE_MASK);

	memcpy(ptr, src, bytes);

	put_page_ptr(ptr_page, page);

	return 0;
}

static void restore_backup_data(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm = IKVM(vcpu->kvm);
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	size_t bytes = ikvm->ss_custom_size;
	gva_t gva = ivcpu->ctx_addr;
	u8 *backup;

	if (!bytes)
		return;

	backup = ikvm->ss_custom_data;

	while (bytes) {
		size_t offset = gva & ~PAGE_MASK;
		size_t chunk = min(bytes, PAGE_SIZE - offset);

		if (restore_backup_data_to_page(vcpu, gva, backup, chunk))
			goto out;

		bytes -= chunk;
		backup += chunk;
		gva += chunk;
	}

out:
	ikvm->ss_custom_size = 0;
}

void kvmi_stop_ss(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvm *kvm = vcpu->kvm;
	struct kvmi *ikvm;
	int i;

	ikvm = kvmi_get(kvm);
	if (!ikvm)
		return;

	if (unlikely(!ivcpu->ss_owner)) {
		kvmi_warn(ikvm, "%s\n", __func__);
		goto out;
	}

	for (i = ikvm->ss_level; i--;)
		kvmi_set_gfn_access(kvm,
				    ikvm->ss_context[i].gfn,
				    ikvm->ss_context[i].old_access,
				    ikvm->ss_context[i].old_write_bitmap);

	ikvm->ss_level = 0;

	restore_backup_data(vcpu);

	kvmi_arch_stop_single_step(vcpu);

	atomic_set(&ikvm->ss_active, false);
	/*
	 * Make ss_active update visible
	 * before resuming all the other vCPUs.
	 */
	smp_mb__after_atomic();
	kvm_make_all_cpus_request(kvm, 0);

	ivcpu->ss_owner = false;

	trace_kvmi_stop_singlestep(vcpu->vcpu_id);

	kvmi_singlestep_event(vcpu);

out:
	kvmi_put(kvm);
}
EXPORT_SYMBOL(kvmi_stop_ss);

static bool kvmi_acquire_ss(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvmi *ikvm = IKVM(vcpu->kvm);

	if (ivcpu->ss_owner)
		return true;

	if (atomic_cmpxchg(&ikvm->ss_active, false, true) != false)
		return false;

	kvm_make_all_cpus_request(vcpu->kvm, KVM_REQ_INTROSPECTION |
						KVM_REQUEST_WAIT);

	ivcpu->ss_owner = true;
	ikvm->ss_custom_size = 0;

	return true;
}

static bool kvmi_run_ss(struct kvm_vcpu *vcpu, gpa_t gpa, u8 access)
{
	struct kvmi *ikvm = IKVM(vcpu->kvm);
	u8 old_access, new_access;
	u32 old_write_bitmap;
	gfn_t gfn = gpa_to_gfn(gpa);
	int err;

	trace_kvmi_run_singlestep(vcpu, gpa, access, ikvm->ss_level,
				  IVCPU(vcpu)->ctx_size);

	kvmi_arch_start_single_step(vcpu);

	err = write_custom_data(vcpu);
	if (err) {
		kvmi_err(ikvm, "writing custom data failed, err %d\n", err);
		return false;
	}

	err = kvmi_get_gfn_access(ikvm, gfn, &old_access, &old_write_bitmap);
	/* likely was removed from radix tree due to rwx */
	if (err) {
		kvmi_warn(ikvm, "%s: gfn 0x%llx not found in the radix tree\n",
			  __func__, gfn);
		return true;
	}

	if (ikvm->ss_level == SINGLE_STEP_MAX_DEPTH - 1) {
		kvmi_err(ikvm, "single step limit reached\n");
		return false;
	}

	ikvm->ss_context[ikvm->ss_level].gfn = gfn;
	ikvm->ss_context[ikvm->ss_level].old_access = old_access;
	ikvm->ss_context[ikvm->ss_level].old_write_bitmap = old_write_bitmap;
	ikvm->ss_level++;

	new_access = kvmi_arch_relax_page_access(old_access, access);

	kvmi_set_gfn_access(vcpu->kvm, gfn, new_access, old_write_bitmap);

	return true;
}

bool kvmi_start_ss(struct kvm_vcpu *vcpu, gpa_t gpa, u8 access)
{
	bool ret = false;

	while (!kvmi_acquire_ss(vcpu)) {
		int err = kvmi_run_jobs_and_wait(vcpu);

		if (err) {
			kvmi_err(IKVM(vcpu->kvm), "kvmi_acquire_ss() has failed\n");
			goto out;
		}
	}

	if (kvmi_run_ss(vcpu, gpa, access))
		ret = true;
	else
		kvmi_stop_ss(vcpu);

out:
	return ret;
}

bool kvmi_vcpu_enabled_ss(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvmi *ikvm;
	bool ret;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return false;

	ret = ivcpu->ss_owner;

	kvmi_put(vcpu->kvm);

	return ret;
}
EXPORT_SYMBOL(kvmi_vcpu_enabled_ss);

static void kvmi_job_abort(struct kvm_vcpu *vcpu, void *ctx)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

	/*
	 * The thread that might increment this atomic is stopped
	 * and this thread is the only one that could decrement it.
	 */
	atomic_set(&ivcpu->pause_requests, 0);
	ivcpu->reply_waiting = false;
}

static void kvmi_abort_events(struct kvm *kvm)
{
	int i;
	struct kvm_vcpu *vcpu;

	kvm_for_each_vcpu(i, vcpu, kvm)
		kvmi_add_job(vcpu, kvmi_job_abort, NULL, NULL);
}

static bool __kvmi_unhook_event(struct kvmi *ikvm)
{
	int err;

	if (!test_bit(KVMI_EVENT_UNHOOK, ikvm->vm_ev_mask))
		return false;

	err = kvmi_msg_send_unhook(ikvm);

	return !err;
}

static bool kvmi_unhook_event(struct kvm *kvm)
{
	struct kvmi *ikvm;
	bool ret = true;

	ikvm = kvmi_get(kvm);
	if (!ikvm)
		return false;

	ret = __kvmi_unhook_event(ikvm);

	kvmi_put(kvm);

	return ret;
}

int kvmi_ioctl_unhook(struct kvm *kvm, bool force_reset)
{
	struct kvmi *ikvm;
	int err = 0;

	ikvm = kvmi_get(kvm);
	if (!ikvm)
		return -EFAULT;

	if (force_reset)
		mm_remote_reset();
	else if (!kvmi_unhook_event(kvm))
		err = -ENOENT;

	kvmi_put(kvm);

	return err;
}
