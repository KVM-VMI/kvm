/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVMI_H__
#define __KVMI_H__

#define kvmi_is_present() 1

int kvmi_init(void);
void kvmi_uninit(void);
void kvmi_destroy_vm(struct kvm *kvm);
int kvmi_hook(struct kvm *kvm, struct kvm_introspection *qemu);
void kvmi_vcpu_init(struct kvm_vcpu *vcpu);
void kvmi_vcpu_uninit(struct kvm_vcpu *vcpu);
bool kvmi_cr_event(struct kvm_vcpu *vcpu, unsigned int cr,
		   unsigned long old_value, unsigned long *new_value);
bool kvmi_msr_event(struct kvm_vcpu *vcpu, struct msr_data *msr);
void kvmi_xsetbv_event(struct kvm_vcpu *vcpu);
bool kvmi_breakpoint_event(struct kvm_vcpu *vcpu, u64 gva);
bool kvmi_is_agent_hypercall(struct kvm_vcpu *vcpu);
void kvmi_hypercall_event(struct kvm_vcpu *vcpu);
bool kvmi_lost_exception(struct kvm_vcpu *vcpu);
void kvmi_trap_event(struct kvm_vcpu *vcpu);
bool kvmi_descriptor_event(struct kvm_vcpu *vcpu, u32 info,
			   unsigned long exit_qualification,
			   unsigned char descriptor, unsigned char write);
void kvmi_flush_mem_access(struct kvm *kvm);
void kvmi_handle_request(struct kvm_vcpu *vcpu);
int kvmi_host_mem_map(struct kvm_vcpu *vcpu, gva_t tkn_gva,
			     gpa_t req_gpa, gpa_t map_gpa);
int kvmi_host_mem_unmap(struct kvm_vcpu *vcpu, gpa_t map_gpa);


#endif
