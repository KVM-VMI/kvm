/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVMI_INT_H__
#define __KVMI_INT_H__

#include <linux/kvm_host.h>

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
			  BIT(KVMI_EVENT_UNHOOK) \
		)
#define KVMI_KNOWN_VCPU_EVENTS ( \
			  BIT(KVMI_EVENT_PAUSE_VCPU) \
		)

#define KVMI_KNOWN_EVENTS (KVMI_KNOWN_VM_EVENTS | KVMI_KNOWN_VCPU_EVENTS)

#define KVMI_KNOWN_COMMANDS ( \
			  BIT(KVMI_GET_VERSION) \
			| BIT(KVMI_VM_CHECK_COMMAND) \
			| BIT(KVMI_VM_CHECK_EVENT) \
			| BIT(KVMI_VM_CONTROL_EVENTS) \
			| BIT(KVMI_VM_GET_INFO) \
			| BIT(KVMI_VM_READ_PHYSICAL) \
			| BIT(KVMI_VM_WRITE_PHYSICAL) \
			| BIT(KVMI_VCPU_GET_INFO) \
			| BIT(KVMI_VCPU_PAUSE) \
			| BIT(KVMI_VCPU_CONTROL_EVENTS) \
			| BIT(KVMI_VCPU_GET_REGISTERS) \
		)

#define KVMI(kvm) ((struct kvm_introspection *)((kvm)->kvmi))
#define VCPUI(vcpu) ((struct kvm_vcpu_introspection *)((vcpu)->kvmi))

static inline bool is_vm_event_enabled(struct kvm_introspection *kvmi,
					int event)
{
	return test_bit(event, kvmi->vm_event_enable_mask);
}

/* kvmi_msg.c */
bool kvmi_sock_get(struct kvm_introspection *kvmi, int fd);
void kvmi_sock_shutdown(struct kvm_introspection *kvmi);
void kvmi_sock_put(struct kvm_introspection *kvmi);
bool kvmi_msg_process(struct kvm_introspection *kvmi);
int kvmi_msg_send_unhook(struct kvm_introspection *kvmi);
u32 kvmi_msg_send_vcpu_pause(struct kvm_vcpu *vcpu);

/* kvmi.c */
void *kvmi_msg_alloc(void);
void *kvmi_msg_alloc_check(size_t size);
void kvmi_msg_free(void *addr);
int kvmi_add_job(struct kvm_vcpu *vcpu,
		 void (*fct)(struct kvm_vcpu *vcpu, void *ctx),
		 void *ctx, void (*free_fct)(void *ctx));
void kvmi_run_jobs(struct kvm_vcpu *vcpu);
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

/* arch */
int kvmi_arch_cmd_vcpu_get_info(struct kvm_vcpu *vcpu,
				struct kvmi_vcpu_get_info_reply *rpl);
void kvmi_arch_setup_event(struct kvm_vcpu *vcpu, struct kvmi_event *ev);
int kvmi_arch_cmd_vcpu_get_registers(struct kvm_vcpu *vcpu,
				const struct kvmi_msg_hdr *msg,
				const struct kvmi_vcpu_get_registers *req,
				struct kvmi_vcpu_get_registers_reply **dest,
				size_t *dest_size);

#endif
