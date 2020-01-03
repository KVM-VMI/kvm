/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KVMI_HOST_H
#define __KVMI_HOST_H

#include <uapi/linux/kvmi.h>

struct kvm;
struct kvm_vcpu;

#include <asm/kvmi_host.h>

#define KVMI_NUM_COMMANDS KVMI_NUM_MESSAGES

struct kvmi_vcpu_reply {
	int error;
	int action;
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
};

struct kvm_introspection {
	struct kvm_arch_introspection arch;
	struct kvm *kvm;

	uuid_t uuid;

	struct socket *sock;
	struct task_struct *recv;

	DECLARE_BITMAP(cmd_allow_mask, KVMI_NUM_COMMANDS);
	DECLARE_BITMAP(event_allow_mask, KVMI_NUM_EVENTS);

	DECLARE_BITMAP(vm_event_enable_mask, KVMI_NUM_EVENTS);

	atomic_t ev_seq;
};

#ifdef CONFIG_KVM_INTROSPECTION

int kvmi_init(void);
void kvmi_uninit(void);
void kvmi_create_vm(struct kvm *kvm);
void kvmi_destroy_vm(struct kvm *kvm);
void kvmi_vcpu_uninit(struct kvm_vcpu *vcpu);

int kvmi_ioctl_hook(struct kvm *kvm, void __user *argp);
int kvmi_ioctl_unhook(struct kvm *kvm);
int kvmi_ioctl_command(struct kvm *kvm, void __user *argp);
int kvmi_ioctl_event(struct kvm *kvm, void __user *argp);
int kvmi_ioctl_preunhook(struct kvm *kvm);

void kvmi_handle_requests(struct kvm_vcpu *vcpu);

#else

static inline int kvmi_init(void) { return 0; }
static inline void kvmi_uninit(void) { }
static inline void kvmi_create_vm(struct kvm *kvm) { }
static inline void kvmi_destroy_vm(struct kvm *kvm) { }
static inline void kvmi_vcpu_uninit(struct kvm_vcpu *vcpu) { }

static inline void kvmi_handle_requests(struct kvm_vcpu *vcpu) { }

#endif /* CONFIG_KVM_INTROSPECTION */

#endif
