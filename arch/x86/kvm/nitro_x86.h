#ifndef NITRO_X86_H_
#define NITRO_X86_H_

#include <linux/kvm_host.h>

int nitro_set_syscall_trap(struct kvm*,unsigned long*,int);
int nitro_unset_syscall_trap(struct kvm*);

void nitro_wait(struct kvm_vcpu*);
int nitro_report_syscall(struct kvm_vcpu*);
int nitro_report_sysret(struct kvm_vcpu*);
int nitro_report_event(struct kvm_vcpu*);
#endif //NITRO_X86_H_