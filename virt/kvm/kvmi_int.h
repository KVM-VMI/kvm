/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVMI_INT_H__
#define __KVMI_INT_H__

#include <linux/types.h>
#include <linux/kvm_host.h>

#include <uapi/linux/kvmi.h>

#define IVCPU(vcpu) ((struct kvmi_vcpu *)((vcpu)->kvmi))

struct kvmi_vcpu {
	u8 ctx_data[256];
	u32 ctx_size;
	struct semaphore sem_requests;
	unsigned long requests;
	/* TODO: get this ~64KB buffer from a cache */
	u8 msg_buf[KVMI_MAX_MSG_SIZE];
	struct kvmi_event_reply ev_rpl;
	void *ev_rpl_ptr;
	size_t ev_rpl_size;
	size_t ev_rpl_received;
	u32 ev_seq;
	bool ev_rpl_waiting;
	struct {
		u16 error_code;
		u8 nr;
		bool injected;
	} exception;
	struct kvm_regs delayed_regs;
	bool have_delayed_regs;
	bool pause;
};

#define IKVM(kvm) ((struct kvmi *)((kvm)->kvmi))

struct kvmi {
	atomic_t event_mask;
	unsigned long cr_mask;
	struct {
		unsigned long low[BITS_TO_LONGS(8192)];
		unsigned long high[BITS_TO_LONGS(8192)];
	} msr_mask;
	struct radix_tree_root access_tree;
	struct mutex access_tree_lock;
	struct list_head access_list;
	struct work_struct work;
	struct socket *sock;
	rwlock_t sock_lock;
	struct completion finished;
	struct kvm *kvm;
	/* TODO: get this ~64KB buffer from a cache */
	u8 msg_buf[KVMI_MAX_MSG_SIZE];
	u32 cmd_allow_mask;
	u32 event_allow_mask;
};

enum {
	REQ_INIT,
	REQ_CMD,
	REQ_REPLY,
	REQ_CLOSE,
};

/* kvmi_msg.c */
bool kvmi_msg_init(struct kvmi *ikvm, int fd);
bool kvmi_msg_process(struct kvmi *ikvm);
void kvmi_msg_uninit(struct kvmi *ikvm);
void kvmi_msg_handle_vcpu_cmd(struct kvm_vcpu *vcpu);
u32 kvmi_msg_send_cr(struct kvm_vcpu *vcpu, u32 cr, u64 old_value,
		     u64 new_value, u64 *ret_value);
u32 kvmi_msg_send_msr(struct kvm_vcpu *vcpu, u32 msr, u64 old_value,
		      u64 new_value, u64 *ret_value);
u32 kvmi_msg_send_xsetbv(struct kvm_vcpu *vcpu);
u32 kvmi_msg_send_bp(struct kvm_vcpu *vcpu, u64 gpa);
u32 kvmi_msg_send_hypercall(struct kvm_vcpu *vcpu);
u32 kvmi_msg_send_pf(struct kvm_vcpu *vcpu, u64 gpa, u64 gva, u32 mode,
		     bool *trap_access, u8 *ctx, u32 *ctx_size);
u32 kvmi_msg_send_trap(struct kvm_vcpu *vcpu, u32 vector, u32 type,
		       u32 error_code, u64 cr2);
u32 kvmi_msg_send_descriptor(struct kvm_vcpu *vcpu, u32 info,
			     u64 exit_qualification, u8 descriptor, u8 write);
u32 kvmi_msg_send_create_vcpu(struct kvm_vcpu *vcpu);
u32 kvmi_msg_send_pause_vcpu(struct kvm_vcpu *vcpu);

/* kvmi.c */
int kvmi_cmd_get_guest_info(struct kvm_vcpu *vcpu, u16 *vcpu_cnt, u64 *tsc);
int kvmi_cmd_pause_vcpu(struct kvm_vcpu *vcpu);
int kvmi_cmd_get_registers(struct kvm_vcpu *vcpu, u32 *mode,
			   struct kvm_regs *regs, struct kvm_sregs *sregs,
			   struct kvm_msrs *msrs);
int kvmi_cmd_set_registers(struct kvm_vcpu *vcpu, const struct kvm_regs *regs);
int kvmi_cmd_get_page_access(struct kvm_vcpu *vcpu, u64 gpa, u8 *access);
int kvmi_cmd_inject_exception(struct kvm_vcpu *vcpu, u8 vector,
			      bool error_code_valid, u16 error_code,
			      u64 address);
int kvmi_cmd_control_events(struct kvm_vcpu *vcpu, u32 events);
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
int kvmi_cmd_control_cr(struct kvmi *ikvm, bool enable, u32 cr);
int kvmi_cmd_control_msr(struct kvm *kvm, bool enable, u32 msr);
int kvmi_set_mem_access(struct kvm *kvm, u64 gpa, u8 access);
void kvmi_make_request(struct kvmi_vcpu *ivcpu, int req);
void kvmi_clear_request(struct kvmi_vcpu *ivcpu, int req);
unsigned int kvmi_vcpu_mode(const struct kvm_vcpu *vcpu,
			    const struct kvm_sregs *sregs);
void kvmi_get_msrs(struct kvm_vcpu *vcpu, struct kvmi_event *event);
unsigned long gfn_to_hva_safe(struct kvm *kvm, gfn_t gfn);
void kvmi_mem_destroy_vm(struct kvm *kvm);

/* kvmi_mem.c */
int kvmi_store_token(struct kvm *kvm, struct kvmi_map_mem_token *token);

#endif
