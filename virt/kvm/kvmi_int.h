/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVMI_INT_H__
#define __KVMI_INT_H__

#include <linux/types.h>
#include <linux/kvm_host.h>

#include <uapi/linux/kvmi.h>

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

struct kvmi_vcpu {
	struct list_head job_list;
	spinlock_t job_lock;

	bool killed;
};

#define IKVM(kvm) ((struct kvmi *)((kvm)->kvmi))

struct kvmi {
	struct kvm *kvm;

	struct socket *sock;
	struct task_struct *recv;

	uuid_t uuid;

	DECLARE_BITMAP(cmd_allow_mask, KVMI_NUM_COMMANDS);
	DECLARE_BITMAP(event_allow_mask, KVMI_NUM_EVENTS);
	DECLARE_BITMAP(vm_ev_mask, KVMI_NUM_EVENTS);

	bool cmd_reply_disabled;
};

/* kvmi_msg.c */
bool kvmi_sock_get(struct kvmi *ikvm, int fd);
void kvmi_sock_shutdown(struct kvmi *ikvm);
void kvmi_sock_put(struct kvmi *ikvm);
bool kvmi_msg_process(struct kvmi *ikvm);

/* kvmi.c */
void *kvmi_msg_alloc(void);
void *kvmi_msg_alloc_check(size_t size);
void kvmi_msg_free(void *addr);
int kvmi_cmd_control_vm_events(struct kvmi *ikvm, unsigned int event_id,
			       bool enable);
int kvmi_add_job(struct kvm_vcpu *vcpu,
		 void (*fct)(struct kvm_vcpu *vcpu, void *ctx),
		 void *ctx, void (*free_fct)(void *ctx));

#endif
