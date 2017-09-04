#ifndef NITRO_MAIN_H_
#define NITRO_MAIN_H_

#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/kvm_host.h>
#include <linux/nitro.h>

#define NITRO_TRAP_SYSCALL 1UL

// 12 bits -> 1024 entries
#define NITRO_SYSCALL_FILTER_HT_BITS 12

struct syscall_stack_item
{
	uint64_t syscall_nb;
	struct list_head list;
};

// empty entry for the syscall hashtable
// we only need the hashtable to get a O(1) access and
// check if a syscall is present in the filter
struct syscall_filter_ht_entry
{
	struct hlist_node node;
};

struct nitro{
  uint32_t traps; //determines whether the syscall trap is globally set
  DECLARE_HASHTABLE(syscall_filter_ht, NITRO_SYSCALL_FILTER_HT_BITS);
};

struct nitro_vcpu{
  struct completion k_wait_cv;
  struct semaphore n_wait_sem;
  struct event event;
  struct syscall_stack_item stack;
};

struct kvm* nitro_get_vm_by_creator(pid_t);

int nitro_iotcl_num_vms(void);
int nitro_iotcl_attach_vcpus(struct kvm*, struct nitro_vcpus*);


void nitro_create_vm_hook(struct kvm*);
void nitro_destroy_vm_hook(struct kvm*);
void nitro_create_vcpu_hook(struct kvm_vcpu*);
void nitro_destroy_vcpu_hook(struct kvm_vcpu*);

int nitro_ioctl_get_event(struct kvm_vcpu*, struct event *ev);
int nitro_ioctl_continue(struct kvm_vcpu*);

int nitro_is_trap_set(struct kvm*, uint32_t);
int nitro_add_syscall_filter(struct kvm *kvm, uint64_t syscall_nb);
int nitro_remove_syscall_filter(struct kvm *kvm, uint64_t syscall_nb);
int nitro_clear_syscall_filter(struct kvm *kvm);
struct syscall_filter_ht_entry* nitro_find_syscall(struct kvm* kvm, uint64_t syscall_nb);

#endif //NITRO_MAIN_H_
