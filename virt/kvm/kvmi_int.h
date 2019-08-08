/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVMI_INT_H__
#define __KVMI_INT_H__

#include <linux/types.h>
#include <linux/kvm_host.h>

#include <uapi/linux/kvmi.h>
#include <asm/kvmi_host.h>

#define kvmi_debug(ikvm, fmt, ...) \
	kvm_debug("%pU " fmt, &ikvm->uuid, ## __VA_ARGS__)
#define kvmi_info(ikvm, fmt, ...) \
	kvm_info("%pU " fmt, &ikvm->uuid, ## __VA_ARGS__)
#define kvmi_warn(ikvm, fmt, ...) \
	kvm_info("%pU WARNING: " fmt, &ikvm->uuid, ## __VA_ARGS__)
#define kvmi_warn_once(ikvm, fmt, ...) ({                     \
		static bool __section(.data.once) __warned;   \
		if (!__warned) {                              \
			__warned = true;                      \
			kvmi_warn(ikvm, fmt, ## __VA_ARGS__); \
		}                                             \
	})
#define kvmi_err(ikvm, fmt, ...) \
	kvm_info("%pU ERROR: " fmt, &ikvm->uuid, ## __VA_ARGS__)

#define IVCPU(vcpu) ((struct kvmi_vcpu *)((vcpu)->kvmi))

#define KVMI_NUM_CR 9
#define KVMI_NUM_MSR 0x2000
#define KVMI_CTX_DATA_SIZE FIELD_SIZEOF(struct kvmi_event_pf_reply, ctx_data)

#define KVMI_MSG_SIZE_ALLOC (sizeof(struct kvmi_msg_hdr) + KVMI_MSG_SIZE)

#define KVMI_KNOWN_VCPU_EVENTS ( \
		BIT(KVMI_EVENT_CR) | \
		BIT(KVMI_EVENT_MSR) | \
		BIT(KVMI_EVENT_XSETBV) | \
		BIT(KVMI_EVENT_BREAKPOINT) | \
		BIT(KVMI_EVENT_HYPERCALL) | \
		BIT(KVMI_EVENT_PF) | \
		BIT(KVMI_EVENT_TRAP) | \
		BIT(KVMI_EVENT_DESCRIPTOR) | \
		BIT(KVMI_EVENT_PAUSE_VCPU) | \
		BIT(KVMI_EVENT_SINGLESTEP))

#define KVMI_KNOWN_VM_EVENTS ( \
		BIT(KVMI_EVENT_CREATE_VCPU) | \
		BIT(KVMI_EVENT_UNHOOK))

#define KVMI_KNOWN_EVENTS (KVMI_KNOWN_VCPU_EVENTS | KVMI_KNOWN_VM_EVENTS)

#define KVMI_KNOWN_COMMANDS ( \
		BIT(KVMI_GET_VERSION) | \
		BIT(KVMI_CHECK_COMMAND) | \
		BIT(KVMI_CHECK_EVENT) | \
		BIT(KVMI_GET_GUEST_INFO) | \
		BIT(KVMI_PAUSE_VCPU) | \
		BIT(KVMI_CONTROL_VM_EVENTS) | \
		BIT(KVMI_CONTROL_EVENTS) | \
		BIT(KVMI_CONTROL_CR) | \
		BIT(KVMI_CONTROL_MSR) | \
		BIT(KVMI_CONTROL_VE) | \
		BIT(KVMI_GET_REGISTERS) | \
		BIT(KVMI_SET_REGISTERS) | \
		BIT(KVMI_GET_CPUID) | \
		BIT(KVMI_GET_XSAVE) | \
		BIT(KVMI_READ_PHYSICAL) | \
		BIT(KVMI_WRITE_PHYSICAL) | \
		BIT(KVMI_INJECT_EXCEPTION) | \
		BIT(KVMI_GET_PAGE_ACCESS) | \
		BIT(KVMI_SET_PAGE_ACCESS) | \
		BIT(KVMI_GET_MAP_TOKEN) | \
		BIT(KVMI_CONTROL_SPP) | \
		BIT(KVMI_GET_PAGE_WRITE_BITMAP) | \
		BIT(KVMI_SET_PAGE_WRITE_BITMAP) | \
		BIT(KVMI_GET_MTRR_TYPE) | \
		BIT(KVMI_CONTROL_CMD_RESPONSE) | \
		BIT(KVMI_GET_VCPU_INFO))

#define KVMI_NUM_COMMANDS KVMI_NEXT_AVAILABLE_COMMAND

struct kvmi_job {
	struct list_head link;
	void *ctx;
	void (*fct)(struct kvm_vcpu *vcpu, void *ctx);
	void (*free_fct)(void *ctx);
};

struct kvmi_vcpu_reply {
	int error;
	int action;
	u32 seq;
	void *data;
	size_t size;
};

struct kvmi_vcpu {
	u8 ctx_data[KVMI_CTX_DATA_SIZE];
	u32 ctx_size;
	u64 ctx_addr;
	bool rep_complete;
	bool effective_rep_complete;

	atomic_t pause_requests;

	bool reply_waiting;
	struct kvmi_vcpu_reply reply;

	struct {
		u8 nr;
		u32 error_code;
		bool error_code_valid;
		u64 address;
		bool pending;
	} exception;

	bool have_delayed_regs;
	struct kvm_regs delayed_regs;

	bool bp_intercepted;
	DECLARE_BITMAP(ev_mask, KVMI_NUM_EVENTS);
	DECLARE_BITMAP(cr_mask, KVMI_NUM_CR);
	struct {
		DECLARE_BITMAP(low, KVMI_NUM_MSR);
		DECLARE_BITMAP(high, KVMI_NUM_MSR);
	} msr_mask;

	bool ss_owner;
	bool ss_requested;

	struct list_head job_list;
	spinlock_t job_lock;

	bool killed;
};

#define IKVM(kvm) ((struct kvmi *)((kvm)->kvmi))

struct kvmi {
	struct kvm *kvm;
	struct kvm_page_track_notifier_node kptn_node;

	struct radix_tree_root access_tree;
	rwlock_t access_tree_lock;

	struct socket *sock;
	struct task_struct *recv;
	atomic_t ev_seq;

	uuid_t uuid;

	DECLARE_BITMAP(cmd_allow_mask, KVMI_NUM_COMMANDS);
	DECLARE_BITMAP(event_allow_mask, KVMI_NUM_EVENTS);
	DECLARE_BITMAP(vm_ev_mask, KVMI_NUM_EVENTS);

#define SINGLE_STEP_MAX_DEPTH 8
	struct {
		gfn_t gfn;
		u8 old_access;
		u32 old_write_bitmap;
	} ss_context[SINGLE_STEP_MAX_DEPTH];
	u8 ss_custom_data[KVMI_CTX_DATA_SIZE];
	size_t ss_custom_size;
	gpa_t ss_custom_addr;
	u8 ss_level;
	atomic_t ss_active;

	struct {
		bool initialized;
		atomic_t enabled;
	} spp;

	bool cmd_reply_disabled;
};

struct kvmi_mem_access {
	gfn_t gfn;
	u8 access;
	u32 write_bitmap;
	struct kvmi_arch_mem_access arch;
};

static inline bool is_event_enabled(struct kvm_vcpu *vcpu, int event)
{
	return test_bit(event, IVCPU(vcpu)->ev_mask);
}

static inline bool kvmi_spp_enabled(struct kvmi *ikvm)
{
	return atomic_read(&ikvm->spp.enabled);
}

/* kvmi_msg.c */
bool kvmi_sock_get(struct kvmi *ikvm, int fd);
void kvmi_sock_shutdown(struct kvmi *ikvm);
void kvmi_sock_put(struct kvmi *ikvm);
bool kvmi_msg_process(struct kvmi *ikvm);
int kvmi_send_event(struct kvm_vcpu *vcpu, u32 ev_id,
		    void *ev, size_t ev_size,
		    void *rpl, size_t rpl_size, int *action);
u32 kvmi_msg_send_bp(struct kvm_vcpu *vcpu, u64 gpa, u8 insn_len);
u32 kvmi_msg_send_hypercall(struct kvm_vcpu *vcpu);
u32 kvmi_msg_send_pf(struct kvm_vcpu *vcpu, u64 gpa, u64 gva, u8 access,
		     bool *singlestep, bool *rep_complete,
		     u64 *ctx_addr, u8 *ctx, u32 *ctx_size);
u32 kvmi_msg_send_descriptor(struct kvm_vcpu *vcpu, u8 descriptor, u8 write);
u32 kvmi_msg_send_create_vcpu(struct kvm_vcpu *vcpu);
u32 kvmi_msg_send_pause_vcpu(struct kvm_vcpu *vcpu);
int kvmi_msg_send_unhook(struct kvmi *ikvm);

/* kvmi.c */
void *kvmi_msg_alloc(void);
void *kvmi_msg_alloc_check(size_t size);
void kvmi_msg_free(void *addr);
int kvmi_cmd_set_registers(struct kvm_vcpu *vcpu, const struct kvm_regs *regs);
int kvmi_cmd_get_page_access(struct kvmi *ikvm, u64 gpa, u8 *access);
int kvmi_cmd_set_page_access(struct kvmi *ikvm, u64 gpa, u8 access);
int kvmi_cmd_get_page_write_bitmap(struct kvmi *ikvm, u64 gpa, u32 *bitmap);
int kvmi_cmd_set_page_write_bitmap(struct kvmi *ikvm, u64 gpa, u32 bitmap);
int kvmi_cmd_read_physical(struct kvm *kvm, u64 gpa, u64 size,
			   int (*send)(struct kvmi *,
					const struct kvmi_msg_hdr*,
					int err, const void *buf, size_t),
			   const struct kvmi_msg_hdr *ctx);
int kvmi_cmd_write_physical(struct kvm *kvm, u64 gpa, u64 size,
			    const void *buf);
int kvmi_cmd_control_events(struct kvm_vcpu *vcpu, unsigned int event_id,
			    bool enable);
int kvmi_cmd_control_vm_events(struct kvmi *ikvm, unsigned int event_id,
			       bool enable);
int kvmi_cmd_pause_vcpu(struct kvm_vcpu *vcpu, bool wait);
struct kvmi * __must_check kvmi_get(struct kvm *kvm);
void kvmi_put(struct kvm *kvm);
int kvmi_run_jobs_and_wait(struct kvm_vcpu *vcpu);
void kvmi_post_reply(struct kvm_vcpu *vcpu);
int kvmi_add_job(struct kvm_vcpu *vcpu,
		 void (*fct)(struct kvm_vcpu *vcpu, void *ctx),
		 void *ctx, void (*free_fct)(void *ctx));
void kvmi_handle_common_event_actions(struct kvm_vcpu *vcpu, u32 action,
				      const char *str);
bool kvmi_start_ss(struct kvm_vcpu *vcpu, gpa_t gpa, u8 access);

/* arch */
void kvmi_arch_update_page_tracking(struct kvm *kvm,
				    struct kvm_memory_slot *slot,
				    struct kvmi_mem_access *m);
int kvmi_arch_cmd_control_event(struct kvm_vcpu *vcpu, unsigned int event_id,
				bool enable);
int kvmi_arch_cmd_get_registers(struct kvm_vcpu *vcpu,
				const struct kvmi_msg_hdr *msg,
				const struct kvmi_get_registers *req,
				struct kvmi_get_registers_reply **dest,
				size_t *dest_size);
int kvmi_arch_cmd_get_page_access(struct kvmi *ikvm,
				  const struct kvmi_msg_hdr *msg,
				  const struct kvmi_get_page_access *req,
				  struct kvmi_get_page_access_reply **dest,
				  size_t *dest_size);
int kvmi_arch_cmd_set_page_access(struct kvmi *ikvm,
				  const struct kvmi_msg_hdr *msg,
				  const struct kvmi_set_page_access *req);
int kvmi_arch_cmd_control_spp(struct kvmi *ikvm);
int kvmi_arch_cmd_get_page_write_bitmap(struct kvmi *ikvm,
					const struct kvmi_msg_hdr *msg,
					const struct kvmi_get_page_write_bitmap *req,
					struct kvmi_get_page_write_bitmap_reply **dest,
					size_t *dest_size);
int kvmi_arch_cmd_set_page_write_bitmap(struct kvmi *ikvm,
					const struct kvmi_msg_hdr *msg,
					const struct kvmi_set_page_write_bitmap *req);
void kvmi_arch_setup_event(struct kvm_vcpu *vcpu, struct kvmi_event *ev);
bool kvmi_arch_pf_event(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
			u8 access);
bool kvmi_arch_queue_exception(struct kvm_vcpu *vcpu);
void kvmi_arch_trap_event(struct kvm_vcpu *vcpu);
void kvmi_arch_breakpoint_event(struct kvm_vcpu *vcpu, u64 gva, u8 insn_len);
bool kvmi_arch_is_agent_hypercall(struct kvm_vcpu *vcpu);
void kvmi_arch_hypercall_event(struct kvm_vcpu *vcpu);
int kvmi_arch_cmd_get_cpuid(struct kvm_vcpu *vcpu,
			    const struct kvmi_get_cpuid *req,
			    struct kvmi_get_cpuid_reply *rpl);
int kvmi_arch_cmd_get_xsave(struct kvm_vcpu *vcpu,
			    struct kvmi_get_xsave_reply **dest,
			    size_t *dest_size);
int kvmi_arch_cmd_get_vcpu_info(struct kvm_vcpu *vcpu,
				struct kvmi_get_vcpu_info_reply *rpl);
int kvmi_arch_cmd_inject_exception(struct kvm_vcpu *vcpu, u8 vector,
				   bool error_code_valid, u32 error_code,
				   u64 address);
int kvmi_arch_cmd_control_cr(struct kvm_vcpu *vcpu,
			     const struct kvmi_control_cr *req);
bool is_ud2_instruction(struct kvm_vcpu *vcpu, int *emulation_type);
void kvmi_arch_start_single_step(struct kvm_vcpu *vcpu);
void kvmi_arch_stop_single_step(struct kvm_vcpu *vcpu);
u8 kvmi_arch_relax_page_access(u8 old, u8 new);
int kvmi_arch_cmd_control_msr(struct kvm_vcpu *vcpu,
			      const struct kvmi_control_msr *req);
int kvmi_arch_cmd_get_mtrr_type(struct kvm_vcpu *vcpu, u64 gpa, u8 *type);

#endif
