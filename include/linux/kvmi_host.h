/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KVMI_HOST_H
#define __KVMI_HOST_H

#ifdef CONFIG_KVM_INTROSPECTION

#include <asm/kvmi_host.h>

struct kvmi_vcpu_reply {
	int error;
	u32 action;
	u32 seq;
	void *data;
	size_t size;
};

struct kvmi_job {
	struct list_head link;
	void *ctx;
	void (*fct)(struct kvm_vcpu *vcpu, void *ctx);
	void (*free_fct)(void *ctx);
};

struct kvm_vcpu_introspection {
	struct kvm_vcpu_arch_introspection arch;

	struct list_head job_list;
	spinlock_t job_lock;

	atomic_t pause_requests;

	struct kvmi_vcpu_reply reply;
	bool waiting_for_reply;

	unsigned long *ev_enable_mask;
};

struct kvm_introspection {
	struct kvm_arch_introspection arch;
	struct kvm *kvm;

	uuid_t uuid;

	struct socket *sock;
	struct task_struct *recv;

	unsigned long *cmd_allow_mask;
	unsigned long *event_allow_mask;

	unsigned long *vm_event_enable_mask;

	atomic_t ev_seq;
};

int kvmi_version(void);
int kvmi_init(void);
void kvmi_uninit(void);
void kvmi_create_vm(struct kvm *kvm);
void kvmi_destroy_vm(struct kvm *kvm);
void kvmi_vcpu_uninit(struct kvm_vcpu *vcpu);

int kvmi_ioctl_hook(struct kvm *kvm,
		    const struct kvm_introspection_hook *hook);
int kvmi_ioctl_unhook(struct kvm *kvm);
int kvmi_ioctl_command(struct kvm *kvm,
		       const struct kvm_introspection_feature *feat);
int kvmi_ioctl_event(struct kvm *kvm,
		     const struct kvm_introspection_feature *feat);
int kvmi_ioctl_preunhook(struct kvm *kvm);

void kvmi_handle_requests(struct kvm_vcpu *vcpu);
bool kvmi_hypercall_event(struct kvm_vcpu *vcpu);
bool kvmi_breakpoint_event(struct kvm_vcpu *vcpu, u64 gva, u8 insn_len);

#else

static inline int kvmi_version(void) { return 0; }
static inline int kvmi_init(void) { return 0; }
static inline void kvmi_uninit(void) { }
static inline void kvmi_create_vm(struct kvm *kvm) { }
static inline void kvmi_destroy_vm(struct kvm *kvm) { }
static inline void kvmi_vcpu_uninit(struct kvm_vcpu *vcpu) { }

static inline void kvmi_handle_requests(struct kvm_vcpu *vcpu) { }
static inline bool kvmi_hypercall_event(struct kvm_vcpu *vcpu) { return false; }
static inline bool kvmi_breakpoint_event(struct kvm_vcpu *vcpu, u64 gva,
					 u8 insn_len) { return true; }

#endif /* CONFIG_KVM_INTROSPECTION */

#endif
