/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_KVM_PAGE_TRACK_H
#define _ASM_X86_KVM_PAGE_TRACK_H

enum kvm_page_track_mode {
	KVM_PAGE_TRACK_PREREAD,
	KVM_PAGE_TRACK_PREWRITE,
	KVM_PAGE_TRACK_WRITE,
	KVM_PAGE_TRACK_PREEXEC,
	KVM_PAGE_TRACK_SVE,
	KVM_PAGE_TRACK_MAX,
};

/*
 * The notifier represented by @kvm_page_track_notifier_node is linked into
 * the head which will be notified when guest is triggering the track event.
 *
 * Write access on the head is protected by kvm->mmu_lock, read access
 * is protected by track_srcu.
 */
struct kvm_page_track_notifier_head {
	struct srcu_struct track_srcu;
	struct hlist_head track_notifier_list;
};

struct kvm_page_track_notifier_node {
	struct hlist_node node;

	/*
	 * It is called when guest is reading the read-tracked page
	 * and the read emulation is about to happen.
	 *
	 * @vcpu: the vcpu where the read access happened.
	 * @gpa: the physical address read by guest.
	 * @gva: the virtual address read by guest.
	 * @new: the data to be used.
	 * @bytes: the read length.
	 * @data_ready: set to true if 'new' is filled by the tracker.
	 * @node: this node.
	 */
	bool (*track_preread)(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
			      u8 *new, int bytes, bool *data_ready,
			      struct kvm_page_track_notifier_node *node);
	/*
	 * It is called when guest is writing the write-tracked page
	 * and the write emulation didn't happened yet.
	 *
	 * @vcpu: the vcpu where the write access happened.
	 * @gpa: the physical address written by guest.
	 * @gva: the virtual address written by guest.
	 * @new: the data was written to the address.
	 * @bytes: the written length.
	 * @node: this node
	 */
	bool (*track_prewrite)(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
			       const u8 *new, int bytes,
			       struct kvm_page_track_notifier_node *node);
	/*
	 * It is called when guest is writing the write-tracked page
	 * and write emulation is finished at that time.
	 *
	 * @vcpu: the vcpu where the write access happened.
	 * @gpa: the physical address written by guest.
	 * @gva: the virtual address written by guest.
	 * @new: the data was written to the address.
	 * @bytes: the written length.
	 * @node: this node
	 */
	void (*track_write)(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
			    const u8 *new, int bytes,
			    struct kvm_page_track_notifier_node *node);
	/*
	 * It is called when guest is fetching from a exec-tracked page
	 * and the fetch emulation is about to happen.
	 *
	 * @vcpu: the vcpu where the fetch access happened.
	 * @gpa: the physical address fetched by guest.
	 * @gva: the virtual address fetched by guest.
	 * @node: this node.
	 */
	bool (*track_preexec)(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
			      struct kvm_page_track_notifier_node *node);
	/*
	 * It is called when memory slot is being created
	 *
	 * @kvm: the kvm where memory slot being moved or removed
	 * @slot: the memory slot being moved or removed
	 * @npages: the number of pages
	 * @node: this node
	 */
	void (*track_create_slot)(struct kvm *kvm, struct kvm_memory_slot *slot,
				  unsigned long npages,
				  struct kvm_page_track_notifier_node *node);
	/*
	 * It is called when memory slot is being moved or removed
	 * users can drop active protection for the pages in that memory slot
	 *
	 * @kvm: the kvm where memory slot being moved or removed
	 * @slot: the memory slot being moved or removed
	 * @node: this node
	 */
	void (*track_flush_slot)(struct kvm *kvm, struct kvm_memory_slot *slot,
			    struct kvm_page_track_notifier_node *node);
};

void kvm_page_track_init(struct kvm *kvm);
void kvm_page_track_cleanup(struct kvm *kvm);

void kvm_page_track_free_memslot(u16 count,
				 struct kvm_memory_slot *free,
				 struct kvm_memory_slot *dont);
int kvm_page_track_create_memslot(struct kvm *kvm, struct kvm_memory_slot *slot,
				  unsigned long npages);

void kvm_slot_page_track_add_page(struct kvm *kvm,
				  struct kvm_memory_slot *slot, gfn_t gfn,
				  enum kvm_page_track_mode mode, u16 view);
void kvm_slot_page_track_remove_page(struct kvm *kvm,
				     struct kvm_memory_slot *slot, gfn_t gfn,
				     enum kvm_page_track_mode mode, u16 view);
bool kvm_page_track_is_active(struct kvm_vcpu *vcpu, gfn_t gfn,
			      enum kvm_page_track_mode mode);

void
kvm_page_track_register_notifier(struct kvm *kvm,
				 struct kvm_page_track_notifier_node *n);
void
kvm_page_track_unregister_notifier(struct kvm *kvm,
				   struct kvm_page_track_notifier_node *n);
bool kvm_page_track_preread(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
			    u8 *new, int bytes, bool *data_ready);
bool kvm_page_track_prewrite(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
			     const u8 *new, int bytes);
void kvm_page_track_write(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
			  const u8 *new, int bytes);
bool kvm_page_track_preexec(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva);
void kvm_page_track_flush_slot(struct kvm *kvm, struct kvm_memory_slot *slot);
#endif
