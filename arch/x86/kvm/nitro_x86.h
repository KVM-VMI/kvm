#ifndef NITRO_X86_H_
#define NITRO_X86_H_

#include <linux/kvm_host.h>

int nitro_set_syscall_trap(struct kvm*, bool enabled);
void nitro_wait(struct kvm_vcpu*);
void nitro_report_event(struct kvm_vcpu*);
inline u64 nitro_get_efer(struct kvm_vcpu*);
u64 nitro_get_old_sysenter_cs(void);


#endif //NITRO_X86_H_
