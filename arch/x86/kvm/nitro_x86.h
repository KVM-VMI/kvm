#ifndef NITRO_X86_H_
#define NITRO_X86_H_

#include <linux/kvm_host.h>

int nitro_set_syscall_trap(struct kvm*,unsigned long*,int);
int nitro_unset_syscall_trap(struct kvm*);

int nitro_handle_syscall_trap(struct kvm_vcpu*);

#endif //NITRO_X86_H_