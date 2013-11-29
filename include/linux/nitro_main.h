#ifndef NITRO_MAIN_H_
#define NITRO_MAIN_H_

#include <linux/list.h>
#include <linux/types.h>
#include <linux/kvm_host.h>
#include <linux/nitro.h>


struct nitro{
  int trap_syscall; //determines whether the syscall trap is globally set
};

struct nitro_vcpu{
  int trap_syscall_hit;
  struct completion k_wait_cv;
  struct semaphore n_wait_sem;
  int event;
};
  

struct kvm* nitro_get_vm_by_creator(pid_t);

int nitro_iotcl_num_vms(void);
int nitro_iotcl_attach_vcpus(struct kvm*, struct nitro_vcpus*);


void nitro_create_vm_hook(struct kvm*);
void nitro_destroy_vm_hook(struct kvm*);
void nitro_create_vcpu_hook(struct kvm_vcpu*);
void nitro_destroy_vcpu_hook(struct kvm_vcpu*);

int nitro_ioctl_get_event(struct kvm_vcpu*);
int nitro_ioctl_continue(struct kvm_vcpu*);

#endif //NITRO_MAIN_H_