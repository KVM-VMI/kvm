#ifndef NITRO_X86_H_
#define NITRO_X86_H_

#include <linux/kvm_host.h>

int nitro_set_syscall_trap(struct kvm*, bool enabled);
void nitro_wait(struct kvm_vcpu*);
void nitro_report_event(struct kvm_vcpu*, uint64_t syscall_nb);
void nitro_process_event(struct kvm_vcpu*);
u64 nitro_get_efer(struct kvm_vcpu*);
u64 nitro_get_old_sysenter_cs(void);
bool nitro_get_syscall_num(struct kvm_vcpu *vcpu, uint64_t *result);
bool nitro_should_propagate(struct kvm_vcpu *vcpu);
void nitro_do_continue(struct kvm_vcpu *vcpu);
void nitro_do_continue_step_over(struct kvm_vcpu *vcpu);


#endif //NITRO_X86_H_
