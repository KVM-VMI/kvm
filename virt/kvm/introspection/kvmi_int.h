/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVMI_INT_H__
#define __KVMI_INT_H__

#include <linux/kvm_host.h>

#define kvmi_info(kvmi, fmt, ...) \
	kvm_info("%pU " fmt, &kvmi->uuid, ## __VA_ARGS__)
#define kvmi_warn(kvmi, fmt, ...) \
	kvm_info("%pU WARNING: " fmt, &kvmi->uuid, ## __VA_ARGS__)
#define kvmi_warn_once(kvmi, fmt, ...) ({                     \
		static bool __section(.data.once) __warned;   \
		if (!__warned) {                              \
			__warned = true;                      \
			kvmi_warn(kvmi, fmt, ## __VA_ARGS__); \
		}                                             \
	})
#define kvmi_err(kvmi, fmt, ...) \
	kvm_info("%pU ERROR: " fmt, &kvmi->uuid, ## __VA_ARGS__)

#define KVMI_MSG_SIZE_ALLOC (sizeof(struct kvmi_msg_hdr) + KVMI_MSG_SIZE)

#define KVMI_KNOWN_VM_EVENTS ( \
			  BIT(KVMI_EVENT_CREATE_VCPU) | \
			  BIT(KVMI_EVENT_CMD_ERROR) | \
			  BIT(KVMI_EVENT_UNHOOK) \
		)
#define KVMI_KNOWN_VCPU_EVENTS ( \
			    BIT(KVMI_EVENT_BREAKPOINT) \
			  | BIT(KVMI_EVENT_CMD_ERROR) \
			  | BIT(KVMI_EVENT_CR) \
			  | BIT(KVMI_EVENT_DESCRIPTOR) \
			  | BIT(KVMI_EVENT_HYPERCALL) \
			  | BIT(KVMI_EVENT_MSR) \
			  | BIT(KVMI_EVENT_TRAP) \
			  | BIT(KVMI_EVENT_PAUSE_VCPU) \
			  | BIT(KVMI_EVENT_PF) \
			  | BIT(KVMI_EVENT_SINGLESTEP) \
			  | BIT(KVMI_EVENT_XSETBV) \
			  | BIT(KVMI_EVENT_CPUID) \
		)

#define KVMI_KNOWN_EVENTS (KVMI_KNOWN_VM_EVENTS | KVMI_KNOWN_VCPU_EVENTS)

#define KVMI_KNOWN_COMMANDS ( \
			  BIT(KVMI_GET_VERSION) \
			| BIT(KVMI_VM_CHECK_COMMAND) \
			| BIT(KVMI_VM_CHECK_EVENT) \
			| BIT(KVMI_VM_CONTROL_CMD_RESPONSE) \
			| BIT(KVMI_VM_CONTROL_EVENTS) \
			| BIT(KVMI_VM_CONTROL_SPP) \
			| BIT(KVMI_VM_GET_INFO) \
			| BIT(KVMI_VM_GET_MAP_TOKEN) \
			| BIT(KVMI_VM_GET_MAX_GFN) \
			| BIT(KVMI_VM_READ_PHYSICAL) \
			| BIT(KVMI_VM_SET_PAGE_ACCESS) \
			| BIT(KVMI_VM_SET_PAGE_SVE) \
			| BIT(KVMI_VM_WRITE_PHYSICAL) \
			| BIT(KVMI_VCPU_GET_INFO) \
			| BIT(KVMI_VCPU_PAUSE) \
			| BIT(KVMI_VCPU_CHANGE_GFN) \
			| BIT(KVMI_VCPU_CONTROL_CR) \
			| BIT(KVMI_VCPU_CONTROL_EPT_VIEW) \
			| BIT(KVMI_VCPU_CONTROL_EVENTS) \
			| BIT(KVMI_VCPU_CONTROL_MSR) \
			| BIT(KVMI_VCPU_CONTROL_SINGLESTEP) \
			| BIT(KVMI_VCPU_DISABLE_VE) \
			| BIT(KVMI_VCPU_GET_CPUID) \
			| BIT(KVMI_VCPU_GET_EPT_VIEW) \
			| BIT(KVMI_VCPU_GET_MTRR_TYPE) \
			| BIT(KVMI_VCPU_GET_REGISTERS) \
			| BIT(KVMI_VCPU_GET_XCR) \
			| BIT(KVMI_VCPU_GET_XSAVE) \
			| BIT(KVMI_VCPU_INJECT_EXCEPTION) \
			| BIT(KVMI_VCPU_SET_EPT_VIEW) \
			| BIT(KVMI_VCPU_SET_REGISTERS) \
			| BIT(KVMI_VCPU_SET_XSAVE) \
			| BIT(KVMI_VCPU_SET_VE_INFO) \
			| BIT(KVMI_VCPU_TRANSLATE_GVA) \
		)

#define KVMI(kvm) ((struct kvm_introspection *)((kvm)->kvmi))
#define VCPUI(vcpu) ((struct kvm_vcpu_introspection *)((vcpu)->kvmi))

struct kvmi_mem_access {
	gfn_t gfn;
	u8 access;
	u32 write_bitmap;
};

/*
 * The SVA requests a mapping of a GPA from the host (doesn't know the length).
 * The host looks up the memslot containing that GPA in the source machine.
 * The host then returns the memory range info to the guest in this struct.
 */
struct kvmi_mem_map {
	uuid_t dom_id;		/* in - domain ID */
	gpa_t req_gpa;		/* in - address to look for */
	size_t min_map;		/* in - min length of memory to hotplug */

	gpa_t req_start;	/* out - starting GPA of guest memslot */
	size_t req_length;	/* out - length of guest memslot */
	gpa_t map_start;	/* out - local GPA where QEMU hotplugged mirror DIMM */
};

struct kvmi_mem_unmap {
	uuid_t dom_id;		/* in - domain ID */
	gpa_t map_gpa;		/* in - local GPA */
};

static inline bool is_vm_event_enabled(struct kvm_introspection *kvmi,
					int event)
{
	return test_bit(event, kvmi->vm_event_enable_mask);
}

static inline bool is_event_enabled(struct kvm_vcpu *vcpu, int event)
{
	return test_bit(event, VCPUI(vcpu)->ev_mask);
}

static inline bool is_valid_view(unsigned short view)
{
	return (view < KVM_MAX_EPT_VIEWS);
}

static inline bool kvmi_spp_enabled(struct kvm_introspection *kvmi)
{
	return READ_ONCE(kvmi->arch.spp.enabled);
}

/* kvmi_msg.c */
bool kvmi_sock_get(struct kvm_introspection *kvmi, int fd);
void kvmi_sock_shutdown(struct kvm_introspection *kvmi);
void kvmi_sock_put(struct kvm_introspection *kvmi);
bool kvmi_msg_process(struct kvm_introspection *kvmi);
int kvmi_send_event(struct kvm_vcpu *vcpu, u32 ev_id,
		    void *ev, size_t ev_size,
		    void *rpl, size_t rpl_size, int *action);
int kvmi_msg_send_unhook(struct kvm_introspection *kvmi);
u32 kvmi_msg_send_vcpu_pause(struct kvm_vcpu *vcpu);
u32 kvmi_msg_send_hypercall(struct kvm_vcpu *vcpu);
u32 kvmi_msg_send_bp(struct kvm_vcpu *vcpu, u64 gpa, u8 insn_len);
u32 kvmi_msg_send_pf(struct kvm_vcpu *vcpu, u64 gpa, u64 gva, u8 access,
		     bool *rep_complete,
		     u64 *ctx_addr, u8 *ctx, u32 *ctx_size);
u32 kvmi_msg_send_create_vcpu(struct kvm_vcpu *vcpu);

/* kvmi.c */
void *kvmi_msg_alloc(void);
void *kvmi_msg_alloc_check(size_t size);
void kvmi_msg_free(void *addr);
int kvmi_add_job(struct kvm_vcpu *vcpu,
		 void (*fct)(struct kvm_vcpu *vcpu, void *ctx),
		 void *ctx, void (*free_fct)(void *ctx));
void kvmi_run_jobs(struct kvm_vcpu *vcpu);
void kvmi_post_reply(struct kvm_vcpu *vcpu);
void kvmi_handle_common_event_actions(struct kvm *kvm,
				      u32 action, const char *str);
struct kvm_introspection * __must_check kvmi_get(struct kvm *kvm);
void kvmi_put(struct kvm *kvm);
void kvmi_send_pending_event(struct kvm_vcpu *vcpu);
int kvmi_cmd_vm_control_events(struct kvm_introspection *kvmi,
				unsigned int event_id, bool enable);
int kvmi_cmd_vcpu_control_events(struct kvm_vcpu *vcpu,
				 unsigned int event_id, bool enable);
int kvmi_cmd_read_physical(struct kvm *kvm, u64 gpa, u64 size,
			   int (*send)(struct kvm_introspection *,
					const struct kvmi_msg_hdr*,
					int err, const void *buf, size_t),
			   const struct kvmi_msg_hdr *ctx);
int kvmi_cmd_write_physical(struct kvm *kvm, u64 gpa, u64 size,
			    const void *buf);
int kvmi_cmd_vcpu_pause(struct kvm_vcpu *vcpu, bool wait);
int kvmi_cmd_vcpu_set_registers(struct kvm_vcpu *vcpu,
				const struct kvm_regs *regs);
int kvmi_cmd_set_page_access(struct kvm_introspection *kvmi, u64 gpa,
			     u8 access, u16 view);
int kvmi_cmd_set_page_sve(struct kvm *kvm, gpa_t gpa, u16 view, bool suppress);
int kvmi_cmd_alloc_token(struct kvm *kvm, struct kvmi_map_mem_token *token);
int kvmi_cmd_set_page_write_bitmap(struct kvm_introspection *kvmi, u64 gpa,
					u32 bitmap);

/* arch */
bool kvmi_arch_vcpu_alloc(struct kvm_vcpu *vcpu);
void kvmi_arch_vcpu_free(struct kvm_vcpu *vcpu);
bool kvmi_arch_vcpu_introspected(struct kvm_vcpu *vcpu);
bool kvmi_arch_restore_interception(struct kvm_vcpu *vcpu);
void kvmi_arch_request_restore_interception(struct kvm_vcpu *vcpu);
int kvmi_arch_cmd_vcpu_get_info(struct kvm_vcpu *vcpu,
				struct kvmi_vcpu_get_info_reply *rpl);
void kvmi_arch_setup_event(struct kvm_vcpu *vcpu, struct kvmi_event *ev);
int kvmi_arch_cmd_vcpu_get_registers(struct kvm_vcpu *vcpu,
				const struct kvmi_msg_hdr *msg,
				const struct kvmi_vcpu_get_registers *req,
				struct kvmi_vcpu_get_registers_reply **dest,
				size_t *dest_size);
int kvmi_arch_cmd_vcpu_get_cpuid(struct kvm_vcpu *vcpu,
				 const struct kvmi_vcpu_get_cpuid *req,
				 struct kvmi_vcpu_get_cpuid_reply *rpl);
bool kvmi_arch_is_agent_hypercall(struct kvm_vcpu *vcpu);
void kvmi_arch_hypercall_event(struct kvm_vcpu *vcpu);
void kvmi_arch_breakpoint_event(struct kvm_vcpu *vcpu, u64 gva, u8 insn_len);
int kvmi_arch_cmd_control_intercept(struct kvm_vcpu *vcpu,
				    unsigned int event_id, bool enable);
int kvmi_arch_cmd_vcpu_control_cr(struct kvm_vcpu *vcpu,
				  const struct kvmi_vcpu_control_cr *req);
int kvmi_arch_cmd_vcpu_inject_exception(struct kvm_vcpu *vcpu, u8 vector,
					u32 error_code, u64 address);
void kvmi_arch_trap_event(struct kvm_vcpu *vcpu);
void kvmi_arch_inject_pending_exception(struct kvm_vcpu *vcpu);
int kvmi_arch_cmd_vcpu_get_xsave(struct kvm_vcpu *vcpu,
				 struct kvmi_vcpu_get_xsave_reply **dest,
				 size_t *dest_size);
int kvmi_arch_cmd_set_xsave(struct kvm_vcpu *vcpu,
			    const struct kvmi_vcpu_set_xsave *req,
			    size_t req_size);
int kvmi_arch_cmd_vcpu_get_mtrr_type(struct kvm_vcpu *vcpu, u64 gpa, u8 *type);
int kvmi_arch_cmd_vcpu_control_msr(struct kvm_vcpu *vcpu,
				   const struct kvmi_vcpu_control_msr *req);
void kvmi_arch_update_page_tracking(struct kvm *kvm,
				    struct kvm_memory_slot *slot,
				    gfn_t gfn, u8 access, u8 mask, u16 view);
int kvmi_arch_cmd_set_page_access(struct kvm_introspection *kvmi,
				  const struct kvmi_msg_hdr *msg,
				  const struct kvmi_vm_set_page_access *req);
bool kvmi_arch_pf_event(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
			u8 access);
bool kvmi_arch_pf_of_interest(struct kvm_vcpu *vcpu);
void kvmi_arch_features(struct kvm *kvm, struct kvmi_features *feat);
bool kvmi_arch_start_singlestep(struct kvm_vcpu *vcpu);
bool kvmi_arch_stop_singlestep(struct kvm_vcpu *vcpu);
gpa_t kvmi_arch_cmd_translate_gva(struct kvm_vcpu *vcpu, gva_t gva);
bool kvmi_arch_invalid_insn(struct kvm_vcpu *vcpu, int *emulation_type);
u8 kvmi_arch_relax_page_access(u8 old, u8 new);
u16 kvmi_arch_cmd_get_ept_view(struct kvm_vcpu *vcpu);
int kvmi_arch_cmd_set_ept_view(struct kvm_vcpu *vcpu, u16 view);
int kvmi_arch_cmd_control_ept_view(struct kvm_vcpu *vcpu, u16 view,
				   bool visible);
int kvmi_arch_cmd_set_ve_info(struct kvm_vcpu *vcpu, u64 gpa,
			      bool trigger_vmexit);
int kvmi_arch_cmd_change_gfn(struct kvm_vcpu *vcpu, u64 old_gfn, u64 new_gfn);
int kvmi_arch_cmd_disable_ve(struct kvm_vcpu *vcpu);
int kvmi_arch_cmd_control_spp(struct kvm *kvm);
int kvmi_arch_cmd_set_page_write_bitmap(struct kvm_introspection *kvmi,
			const struct kvmi_msg_hdr *msg,
			const struct kvmi_vm_set_page_write_bitmap *req);
void kvmi_arch_set_subpage_access(struct kvm *kvm,
				  struct kvm_memory_slot *slot,
				  gfn_t gfn, u32 write_bitmap);
u32 kvmi_arch_get_subpage_access(struct kvm_memory_slot *slot, u8 access,
				 gfn_t gfn);
u64 kvmi_arch_cmd_get_xcr(struct kvm_vcpu *vcpu, u8 xcr);

/* kvmi_mem.c */
void kvmi_mem_init(void);
void kvmi_mem_exit(void);
int kvmi_mem_generate_token(struct kvm *kvm, struct kvmi_map_mem_token *token);
void kvmi_clear_vm_tokens(struct kvm *kvm);

#endif
