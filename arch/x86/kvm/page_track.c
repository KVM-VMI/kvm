// SPDX-License-Identifier: GPL-2.0-only
/*
 * Support KVM guest page tracking
 *
 * This feature allows us to track page access in guest. Currently, only
 * write access is tracked.
 *
 * Copyright(C) 2015 Intel Corporation.
 *
 * Author:
 *   Xiao Guangrong <guangrong.xiao@linux.intel.com>
 */

#include <linux/kvm_host.h>
#include <linux/rculist.h>

#include <asm/kvm_host.h>
#include <asm/kvm_page_track.h>

#include "mmu.h"

void kvm_page_track_free_memslot(u16 count,
				 struct kvm_memory_slot *free,
				 struct kvm_memory_slot *dont)
{
	int i, view;

	if (!free->arch.gfn_track || !free->arch.kvmi_track)
		return;

	for (view = 0; view < count; view++) {
		for (i = 0; i < KVM_PAGE_TRACK_MAX; i++)
			if (!dont || !dont->arch.gfn_track
			    || free->arch.gfn_track[view][i] !=
			       dont->arch.gfn_track[view][i]) {
				kvfree(free->arch.gfn_track[view][i]);
				free->arch.gfn_track[view][i] = NULL;

				kvfree(free->arch.kvmi_track[view][i]);
				free->arch.kvmi_track[view][i] = NULL;
			}

		if (!dont || !dont->arch.gfn_track) {
			kvfree(free->arch.gfn_track[view]);
			kvfree(free->arch.kvmi_track[view]);
		}
	}

	if (!dont || !dont->arch.gfn_track) {
		kvfree(free->arch.gfn_track);
		kvfree(free->arch.kvmi_track);
	}
}

int kvm_page_track_create_memslot(struct kvm *kvm, struct kvm_memory_slot *slot,
				  unsigned long npages)
{
	struct kvm_page_track_notifier_head *head;
	struct kvm_page_track_notifier_node *n;
	int view, idx, i;

	for (view = 0; view < kvm->arch.mmu_root_hpa_altviews_count; view++)
		for (i = 0; i < KVM_PAGE_TRACK_MAX; i++) {
			slot->arch.gfn_track[view][i] =
				kvcalloc(npages,
					 sizeof(*slot->arch.gfn_track[view][i]),
					 GFP_KERNEL_ACCOUNT);
			if (!slot->arch.gfn_track[view][i])
				goto track_free;
			slot->arch.kvmi_track[view][i] =
				kvcalloc(BITS_TO_LONGS(npages),
					sizeof(*slot->arch.kvmi_track[view][i]),
					GFP_KERNEL_ACCOUNT);
			if (!slot->arch.kvmi_track[view][i])
				goto track_free;
		}

	head = &kvm->arch.track_notifier_head;

	if (hlist_empty(&head->track_notifier_list))
		return 0;

	idx = srcu_read_lock(&head->track_srcu);
	hlist_for_each_entry_rcu(n, &head->track_notifier_list, node)
		if (n->track_create_slot)
			n->track_create_slot(kvm, slot, npages, n);
	srcu_read_unlock(&head->track_srcu, idx);

	return 0;

track_free:
	kvm_page_track_free_memslot(kvm->arch.mmu_root_hpa_altviews_count, slot, NULL);
	return -ENOMEM;
}

static inline bool page_track_mode_is_valid(enum kvm_page_track_mode mode)
{
	if (mode < 0 || mode >= KVM_PAGE_TRACK_MAX)
		return false;

	return true;
}

static void update_gfn_track(struct kvm_memory_slot *slot, gfn_t gfn,
			     enum kvm_page_track_mode mode, short count,
			     u16 view)
{
	int index, val;

	index = gfn_to_index(gfn, slot->base_gfn, PT_PAGE_TABLE_LEVEL);

	val = slot->arch.gfn_track[view][mode][index];

	if (WARN_ON(val + count < 0 || val + count > USHRT_MAX))
		return;

	slot->arch.gfn_track[view][mode][index] += count;
}

/*
 * add guest page to the tracking pool so that corresponding access on that
 * page will be intercepted.
 *
 * It should be called under the protection both of mmu-lock and kvm->srcu
 * or kvm->slots_lock.
 *
 * @kvm: the guest instance we are interested in.
 * @slot: the @gfn belongs to.
 * @gfn: the guest page.
 * @mode: tracking mode.
 */
void kvm_slot_page_track_add_page(struct kvm *kvm,
				  struct kvm_memory_slot *slot, gfn_t gfn,
				  enum kvm_page_track_mode mode, u16 view)
{

	if (WARN_ON(!page_track_mode_is_valid(mode)))
		return;

	update_gfn_track(slot, gfn, mode, 1, view);

	/*
	 * new track stops large page mapping for the
	 * tracked page.
	 */
	kvm_mmu_gfn_disallow_lpage(slot, gfn);

	if (mode == KVM_PAGE_TRACK_PREWRITE || mode == KVM_PAGE_TRACK_WRITE) {
		if (kvm_mmu_slot_gfn_write_protect(kvm, slot, gfn, view))
			kvm_flush_remote_tlbs(kvm);
	} else if (mode == KVM_PAGE_TRACK_PREREAD) {
		if (kvm_mmu_slot_gfn_read_protect(kvm, slot, gfn, view))
			kvm_flush_remote_tlbs(kvm);
	} else if (mode == KVM_PAGE_TRACK_PREEXEC) {
		if (kvm_mmu_slot_gfn_exec_protect(kvm, slot, gfn, view))
			kvm_flush_remote_tlbs(kvm);
	} else if (mode == KVM_PAGE_TRACK_SVE) {
		if (kvm_mmu_set_ept_page_sve(kvm, slot, gfn, view, false))
			kvm_flush_remote_tlbs(kvm);
	}
}
EXPORT_SYMBOL_GPL(kvm_slot_page_track_add_page);

/*
 * remove the guest page from the tracking pool which stops the interception
 * of corresponding access on that page. It is the opposed operation of
 * kvm_slot_page_track_add_page().
 *
 * It should be called under the protection both of mmu-lock and kvm->srcu
 * or kvm->slots_lock.
 *
 * @kvm: the guest instance we are interested in.
 * @slot: the @gfn belongs to.
 * @gfn: the guest page.
 * @mode: tracking mode.
 */
void kvm_slot_page_track_remove_page(struct kvm *kvm,
				     struct kvm_memory_slot *slot, gfn_t gfn,
				     enum kvm_page_track_mode mode, u16 view)
{
	if (WARN_ON(!page_track_mode_is_valid(mode)))
		return;

	update_gfn_track(slot, gfn, mode, -1, view);

	if (mode == KVM_PAGE_TRACK_SVE)
		if (kvm_mmu_set_ept_page_sve(kvm, slot, gfn, view, true))
			kvm_flush_remote_tlbs(kvm);

	/*
	 * allow large page mapping for the tracked page
	 * after the tracker is gone.
	 */
	kvm_mmu_gfn_allow_lpage(slot, gfn);
}
EXPORT_SYMBOL_GPL(kvm_slot_page_track_remove_page);

/*
 * check if the corresponding access on the specified guest page is tracked.
 */
bool kvm_page_track_is_active(struct kvm_vcpu *vcpu, gfn_t gfn,
			      enum kvm_page_track_mode mode)
{
	struct kvm_memory_slot *slot;
	int index, view;

	if (WARN_ON(!page_track_mode_is_valid(mode)))
		return false;

	slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	if (!slot)
		return false;

	index = gfn_to_index(gfn, slot->base_gfn, PT_PAGE_TABLE_LEVEL);
	view = kvm_get_ept_view(vcpu);
	return !!READ_ONCE(slot->arch.gfn_track[view][mode][index]);
}

void kvm_page_track_cleanup(struct kvm *kvm)
{
	struct kvm_page_track_notifier_head *head;

	head = &kvm->arch.track_notifier_head;
	cleanup_srcu_struct(&head->track_srcu);
}

void kvm_page_track_init(struct kvm *kvm)
{
	struct kvm_page_track_notifier_head *head;

	head = &kvm->arch.track_notifier_head;
	init_srcu_struct(&head->track_srcu);
	INIT_HLIST_HEAD(&head->track_notifier_list);
}

/*
 * register the notifier so that event interception for the tracked guest
 * pages can be received.
 */
void
kvm_page_track_register_notifier(struct kvm *kvm,
				 struct kvm_page_track_notifier_node *n)
{
	struct kvm_page_track_notifier_head *head;

	head = &kvm->arch.track_notifier_head;

	spin_lock(&kvm->mmu_lock);
	hlist_add_head_rcu(&n->node, &head->track_notifier_list);
	spin_unlock(&kvm->mmu_lock);
}
EXPORT_SYMBOL_GPL(kvm_page_track_register_notifier);

/*
 * stop receiving the event interception. It is the opposed operation of
 * kvm_page_track_register_notifier().
 */
void
kvm_page_track_unregister_notifier(struct kvm *kvm,
				   struct kvm_page_track_notifier_node *n)
{
	struct kvm_page_track_notifier_head *head;

	head = &kvm->arch.track_notifier_head;

	spin_lock(&kvm->mmu_lock);
	hlist_del_rcu(&n->node);
	spin_unlock(&kvm->mmu_lock);
	synchronize_srcu(&head->track_srcu);
}
EXPORT_SYMBOL_GPL(kvm_page_track_unregister_notifier);

/*
 * Notify the node that a read access is about to happen. Returning false
 * doesn't stop the other nodes from being called, but it will stop
 * the emulation.
 *
 * The node should figure out if the read page is the one that the node
 * is interested in by itself.
 *
 * The nodes will always be in conflict if they track the same page:
 * - accepting a read won't guarantee that the next node will not override
 *   the data (filling new/bytes and setting data_ready)
 * - filling new/bytes with custom data won't guarantee that the next node
 *   will not override that
 */
bool kvm_page_track_preread(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
			    u8 *new, int bytes, bool *data_ready)
{
	struct kvm_page_track_notifier_head *head;
	struct kvm_page_track_notifier_node *n;
	int idx;
	bool ret = true;

	*data_ready = false;

	head = &vcpu->kvm->arch.track_notifier_head;

	if (hlist_empty(&head->track_notifier_list))
		return ret;

	idx = srcu_read_lock(&head->track_srcu);
	hlist_for_each_entry_rcu(n, &head->track_notifier_list, node)
		if (n->track_preread)
			if (!n->track_preread(vcpu, gpa, gva, new, bytes,
					      data_ready, n))
				ret = false;
	srcu_read_unlock(&head->track_srcu, idx);
	return ret;
}

/*
 * Notify the node that a write access is about to happen. Returning false
 * doesn't stop the other nodes from being called, but it will stop
 * the emulation.
 *
 * The node should figure out if the written page is the one that the node
 * is interested in by itself.
 */
bool kvm_page_track_prewrite(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
			     const u8 *new, int bytes)
{
	struct kvm_page_track_notifier_head *head;
	struct kvm_page_track_notifier_node *n;
	int idx;
	bool ret = true;

	head = &vcpu->kvm->arch.track_notifier_head;

	if (hlist_empty(&head->track_notifier_list))
		return ret;

	idx = srcu_read_lock(&head->track_srcu);
	hlist_for_each_entry_rcu(n, &head->track_notifier_list, node)
		if (n->track_prewrite)
			if (!n->track_prewrite(vcpu, gpa, gva, new, bytes, n))
				ret = false;
	srcu_read_unlock(&head->track_srcu, idx);
	return ret;
}

/*
 * Notify the node that write access is intercepted and write emulation is
 * finished at this time.
 *
 * The node should figure out if the written page is the one that the node
 * is interested in by itself.
 */
void kvm_page_track_write(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
			  const u8 *new, int bytes)
{
	struct kvm_page_track_notifier_head *head;
	struct kvm_page_track_notifier_node *n;
	int idx;

	head = &vcpu->kvm->arch.track_notifier_head;

	if (hlist_empty(&head->track_notifier_list))
		return;

	idx = srcu_read_lock(&head->track_srcu);
	hlist_for_each_entry_rcu(n, &head->track_notifier_list, node)
		if (n->track_write)
			n->track_write(vcpu, gpa, gva, new, bytes, n);
	srcu_read_unlock(&head->track_srcu, idx);
}

/*
 * Notify the node that an instruction is about to be executed.
 * Returning false doesn't stop the other nodes from being called,
 * but it will stop the emulation with X86EMUL_RETRY_INSTR.
 *
 * The node should figure out if the page is the one that the node
 * is interested in by itself.
 */
bool kvm_page_track_preexec(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva)
{
	struct kvm_page_track_notifier_head *head;
	struct kvm_page_track_notifier_node *n;
	int idx;
	bool ret = true;

	head = &vcpu->kvm->arch.track_notifier_head;

	if (hlist_empty(&head->track_notifier_list))
		return ret;

	idx = srcu_read_lock(&head->track_srcu);
	hlist_for_each_entry_rcu(n, &head->track_notifier_list, node)
		if (n->track_preexec)
			if (!n->track_preexec(vcpu, gpa, gva, n))
				ret = false;
	srcu_read_unlock(&head->track_srcu, idx);
	return ret;
}

/*
 * Notify the node that memory slot is being removed or moved so that it can
 * drop active protection for the pages in the memory slot.
 *
 * The node should figure out if the page is the one that the node
 * is interested in by itself.
 */
void kvm_page_track_flush_slot(struct kvm *kvm, struct kvm_memory_slot *slot)
{
	struct kvm_page_track_notifier_head *head;
	struct kvm_page_track_notifier_node *n;
	int idx;

	head = &kvm->arch.track_notifier_head;

	if (hlist_empty(&head->track_notifier_list))
		return;

	idx = srcu_read_lock(&head->track_srcu);
	hlist_for_each_entry_rcu(n, &head->track_notifier_list, node)
		if (n->track_flush_slot)
			n->track_flush_slot(kvm, slot, n);
	srcu_read_unlock(&head->track_srcu, idx);
}
