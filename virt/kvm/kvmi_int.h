/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVMI_INT_H__
#define __KVMI_INT_H__

#include <linux/types.h>
#include <linux/kvm_host.h>
#include <linux/mutex.h>
#include <linux/llist.h>

#include <uapi/linux/kvmi.h>

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

#define kvmi_debug(ikvm, fmt, ...) \
	kvm_debug("%pU " fmt, &ikvm->uuid, ## __VA_ARGS__)

#define IVCPU(vcpu) ((struct kvmi_vcpu *)((vcpu)->kvmi))

#define KVMI_NUM_CR 9
#define KVMI_NUM_MSR 0x2000

struct kvmi_job {
	struct list_head link;
	void *ctx;
	void (*fct)(struct kvm_vcpu *vcpu, void *ctx);
};

struct kvmi_vcpu {
	u8 ctx_data[256];
	u32 ctx_pos;
	u32 ctx_size;
	bool rep_complete;
	bool effective_rep_complete;

	size_t pause_requests;

	bool reply_waiting;

	struct {
		u16 error_code;
		u8 nr;
		bool injected;
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

	struct list_head job_list;
	spinlock_t job_lock;

	bool killed;
};

struct kvmi_reply_cookie {
	struct kvm_vcpu *vcpu;
	struct list_head link;

	u32 seq;
	int error;

	struct kvmi_event_reply reply;
	void *reply_data;
	size_t reply_size;
};

/*
 * Use this macro:
 *   - from the receiving thread (work_cb - VM commands)
 *   - from vCPU threads (once vcpu->kvmi is allocated)
 * Otherwise use kvmi_get(kvm) instead.
 */
#define IKVM(kvm) ((struct kvmi *)((kvm)->kvmi))

struct kvmi_msg {
	atomic_t ev_seq;
	struct list_head rpl_waiters;
	spinlock_t rpl_lock;
};

struct kvmi {
	struct kvm *kvm;
	struct kvm_page_track_notifier_node kptn_node;

	struct radix_tree_root access_tree;
	rwlock_t access_tree_lock;

	struct socket *sock;
	struct kvmi_msg proto;
	struct task_struct *recv;

	u32 cmd_allow_mask;
	u32 event_allow_mask;
	atomic_t num_tokens;

	uuid_t uuid;

	DECLARE_BITMAP(vm_ev_mask, KVMI_NUM_EVENTS);

#define SINGLE_STEP_MAX_DEPTH 8
	struct {
		gfn_t gfn;
		u8 old_access;
	} ss_context[SINGLE_STEP_MAX_DEPTH];
	u8 ss_level;
	atomic_t ss_active;
};

/* kvmi_msg.c */
bool kvmi_sock_get(struct kvmi *ikvm, int fd);
void kvmi_sock_shutdown(struct kvmi *ikvm);
void kvmi_sock_put(struct kvmi *ikvm);
bool kvmi_msg_process(struct kvmi *ikvm);
void kvmi_msg_handle_vcpu_cmd(struct kvm_vcpu *vcpu);
void kvmi_msg_cancel_vcpu_cmd(struct kvmi_vcpu *ivcpu);
void kvmi_msg_wakeup_waiters(struct kvmi *ikvm);
u32 kvmi_msg_send_cr(struct kvm_vcpu *vcpu, u32 cr, u64 old_value,
		     u64 new_value, u64 *ret_value);
u32 kvmi_msg_send_msr(struct kvm_vcpu *vcpu, u32 msr, u64 old_value,
		      u64 new_value, u64 *ret_value);
u32 kvmi_msg_send_xsetbv(struct kvm_vcpu *vcpu);
u32 kvmi_msg_send_bp(struct kvm_vcpu *vcpu, u64 gpa);
u32 kvmi_msg_send_hypercall(struct kvm_vcpu *vcpu);
u32 kvmi_msg_send_pf(struct kvm_vcpu *vcpu, u64 gpa, u64 gva, u32 mode,
		     bool *singlestep, bool *rep_complete,
		     u8 *ctx, u32 *ctx_size);
u32 kvmi_msg_send_trap(struct kvm_vcpu *vcpu, u32 vector, u32 type,
		       u32 error_code, u64 cr2);
u32 kvmi_msg_send_descriptor(struct kvm_vcpu *vcpu, u32 info,
			     u64 exit_qualification, u8 descriptor, u8 write);
u32 kvmi_msg_send_create_vcpu(struct kvm_vcpu *vcpu);
u32 kvmi_msg_send_pause_vcpu(struct kvm_vcpu *vcpu);
u32 kvmi_msg_send_no_emul(struct kvm_vcpu *vcpu, u64 gpa, u64 gva, u32 mode,
			  u8 *insn, size_t insn_size);
int kvmi_msg_send_unhook(struct kvmi *ikvm);

/* kvmi.c */
int kvmi_cmd_get_guest_info(struct kvm_vcpu *vcpu, u32 *vcpu_cnt, u64 *tsc);
int kvmi_cmd_get_registers(struct kvm_vcpu *vcpu, u32 *mode,
			   struct kvm_regs *regs, struct kvm_sregs *sregs,
			   struct kvm_msrs *msrs);
int kvmi_cmd_set_registers(struct kvm_vcpu *vcpu, const struct kvm_regs *regs);
int kvmi_cmd_get_page_access(struct kvm_vcpu *vcpu, u64 gpa, u8 *access);
int kvmi_cmd_set_page_access(struct kvm_vcpu *vcpu, u64 gpa, u8 access);
int kvmi_cmd_inject_exception(struct kvm_vcpu *vcpu, u8 vector,
			      bool error_code_valid, u16 error_code,
			      u64 address);
int kvmi_cmd_control_vm_events(struct kvmi *ikvm, unsigned long event_mask);
int kvmi_cmd_control_events(struct kvm_vcpu *vcpu, unsigned long event_mask);
int kvmi_cmd_control_cr(struct kvm_vcpu *vcpu, bool enable, u32 cr);
int kvmi_cmd_control_msr(struct kvm_vcpu *vcpu, bool enable, u32 msr);
int kvmi_cmd_get_cpuid(struct kvm_vcpu *vcpu, u32 function, u32 index,
		       u32 *eax, u32 *ebx, u32 *rcx, u32 *edx);
int kvmi_cmd_read_physical(struct kvm *kvm, u64 gpa, u64 size,
			   int (*send)(struct kvmi *,
					const struct kvmi_msg_hdr*,
					int err, const void *buf, size_t),
			   const struct kvmi_msg_hdr *ctx);
int kvmi_cmd_write_physical(struct kvm *kvm, u64 gpa, u64 size,
			    const void *buf);
int kvmi_cmd_alloc_token(struct kvm *kvm, struct kvmi_map_mem_token *token);
int kvmi_cmd_pause_all_vcpus(struct kvm *kvm, u32 *vcpu_count);
unsigned int kvmi_vcpu_mode(const struct kvm_vcpu *vcpu,
			    const struct kvm_sregs *sregs);
void kvmi_get_msrs(struct kvm_vcpu *vcpu, struct kvmi_event *event);
unsigned long gfn_to_hva_safe(struct kvm *kvm, gfn_t gfn);
struct kvmi * __must_check kvmi_get(struct kvm *kvm);
void kvmi_put(struct kvm *kvm);
int kvmi_run_jobs_and_wait(struct kvm_vcpu *vcpu);
void kvmi_post_reply(struct kvm_vcpu *vcpu);
int kvmi_add_job(struct kvm_vcpu *vcpu,
		 void (*fct)(struct kvm_vcpu *vcpu, void *ctx),
		 void *ctx);

/* kvmi_mem.c */
int kvmi_mem_init(void);
void kvmi_mem_exit(void);
int kvmi_mem_generate_token(struct kvm *kvm, struct kvmi_map_mem_token *token);
void kvmi_mem_link_down(struct kvm *kvm);

#endif
