#ifndef NITRO_MAIN_H_
#define NITRO_MAIN_H_

#include <linux/list.h>
#include <linux/types.h>
#include <linux/kvm_host.h>
#include <linux/nitro.h>
#include <linux/hashtable.h>

#define NITRO_TRAP_SYSCALL 1UL
//#define NITRO_TRAP_XYZ  (1UL << 1)

struct nitro{
  uint32_t traps; //determines whether the syscall trap is globally set
  unsigned long *system_call_bm;
  unsigned int system_call_max;
  DECLARE_HASHTABLE(system_call_rsp_ht,7);
};

struct nitro_syscall_event_ht{
  ulong rsp;
  ulong cr3;
  struct hlist_node ht;
};

struct nitro_vcpu{
  struct completion k_wait_cv;
  struct semaphore n_wait_sem;
  int event;
  union event_data event_data;
  ulong syscall_event_rsp;
  ulong syscall_event_cr3;
};
  
int nitro_vcpu_load(struct kvm_vcpu*);

struct kvm* nitro_get_vm_by_creator(pid_t);

int nitro_iotcl_num_vms(void);
int nitro_iotcl_attach_vcpus(struct kvm*, struct nitro_vcpus*);


void nitro_create_vm_hook(struct kvm*);
void nitro_destroy_vm_hook(struct kvm*);
void nitro_create_vcpu_hook(struct kvm_vcpu*);
void nitro_destroy_vcpu_hook(struct kvm_vcpu*);

int nitro_ioctl_get_event(struct kvm_vcpu*);
int nitro_ioctl_continue(struct kvm_vcpu*);

inline int nitro_is_trap_set(struct kvm*, uint32_t);

#endif //NITRO_MAIN_H_