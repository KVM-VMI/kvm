/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVMI_INT_H
#define __KVMI_INT_H

#include <linux/kvm_host.h>
#include <linux/kvmi_host.h>
#include <uapi/linux/kvmi.h>

#define KVMI(kvm) ((kvm)->kvmi)
#define VCPUI(vcpu) ((vcpu)->kvmi)
/*
 * This limit is used to accommodate the largest known fixed-length
 * message.
 */
#define KVMI_MAX_MSG_SIZE (4096 * 2 - sizeof(struct kvmi_msg_hdr))

struct kvmi_vcpu_msg_job {
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
	} *msg;
	struct kvm_vcpu *vcpu;
};

typedef int (*kvmi_vcpu_msg_job_fct)(const struct kvmi_vcpu_msg_job *job,
				     const struct kvmi_msg_hdr *msg,
				     const void *req);

/* kvmi_msg.c */
bool kvmi_sock_get(struct kvm_introspection *kvmi, int fd);
void kvmi_sock_shutdown(struct kvm_introspection *kvmi);
void kvmi_sock_put(struct kvm_introspection *kvmi);
bool kvmi_msg_process(struct kvm_introspection *kvmi);
int kvmi_msg_send_unhook(struct kvm_introspection *kvmi);
int kvmi_send_vcpu_event(struct kvm_vcpu *vcpu, u32 ev_id,
			 void *ev, size_t ev_size,
			 void *rpl, size_t rpl_size, u32 *action);
int kvmi_msg_vcpu_reply(const struct kvmi_vcpu_msg_job *job,
			const struct kvmi_msg_hdr *msg, int err,
			const void *rpl, size_t rpl_size);
u32 kvmi_msg_send_vcpu_pause(struct kvm_vcpu *vcpu);

/* kvmi.c */
void *kvmi_msg_alloc(void);
void kvmi_msg_free(void *addr);
bool kvmi_is_command_allowed(struct kvm_introspection *kvmi, u16 id);
bool kvmi_is_event_allowed(struct kvm_introspection *kvmi, u16 id);
bool kvmi_is_known_event(u16 id);
bool kvmi_is_known_vm_event(u16 id);
bool kvmi_is_known_vcpu_event(u16 id);
int kvmi_add_job(struct kvm_vcpu *vcpu,
		 void (*fct)(struct kvm_vcpu *vcpu, void *ctx),
		 void *ctx, void (*free_fct)(void *ctx));
void kvmi_run_jobs(struct kvm_vcpu *vcpu);
int kvmi_cmd_vm_control_events(struct kvm_introspection *kvmi,
			       u16 event_id, bool enable);
int kvmi_cmd_vcpu_control_events(struct kvm_vcpu *vcpu,
				 u16 event_id, bool enable);
int kvmi_cmd_read_physical(struct kvm *kvm, u64 gpa, size_t size,
			   int (*send)(struct kvm_introspection *,
					const struct kvmi_msg_hdr*,
					int err, const void *buf, size_t),
			   const struct kvmi_msg_hdr *ctx);
int kvmi_cmd_write_physical(struct kvm *kvm, u64 gpa, size_t size,
			    const void *buf);
int kvmi_cmd_vcpu_pause(struct kvm_vcpu *vcpu, bool wait);

/* arch */
void kvmi_arch_init_vcpu_events_mask(unsigned long *supported);
kvmi_vcpu_msg_job_fct kvmi_arch_vcpu_msg_handler(u16 id);
void kvmi_arch_setup_vcpu_event(struct kvm_vcpu *vcpu,
				struct kvmi_vcpu_event *ev);

#endif
