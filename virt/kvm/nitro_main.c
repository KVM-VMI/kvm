#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/compiler.h>
#include <asm/current.h>
#include <asm-generic/errno-base.h>
#include <linux/preempt.h>
#include <linux/hashtable.h>

#include <linux/kvm_host.h>

#include <linux/nitro_main.h>
#include <net/irda/parameters.h>

#include "kvm_cache_regs.h"
#include "x86.h"

extern int create_vcpu_fd(struct kvm_vcpu*);

struct kvm* nitro_get_vm_by_creator(pid_t creator){
  struct kvm *rv;
  struct kvm *kvm;
  
  rv = NULL;
  
  spin_lock(&kvm_lock);
  list_for_each_entry(kvm,&vm_list,vm_list)
    if(kvm->mm->owner->pid == creator){
      rv = kvm;
      break;
    }
  spin_unlock(&kvm_lock);
  
  return rv;
}

void nitro_fill_event(struct kvm_vcpu *vcpu, enum syscall_type type, enum syscall_direction direction) {
  printk(KERN_DEBUG "nitro_fill_event: filling nitro event with type %s and direction %s",
         type == SYSCALL ? "syscall" : "sysret",
         direction == ENTER ? "enter" : "exit");
  vcpu->nitro.event.present = true;
  vcpu->nitro.event.type = type;
  vcpu->nitro.event.direction = direction;
  kvm_arch_vcpu_ioctl_get_regs(vcpu, &(vcpu->nitro.event.regs));
  kvm_arch_vcpu_ioctl_get_sregs(vcpu, &(vcpu->nitro.event.sregs));
  // Let's try what Qemu does with this. If we are not interested in this
  // event maybe we shouldn't event exit_here but emulate the event
  // directly
  vcpu->run->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
}
EXPORT_SYMBOL_GPL(nitro_fill_event);

void nitro_create_vm_hook(struct kvm *kvm){
	//init nitro
	kvm->nitro.traps = 0;
	// init syscall filter ht
	hash_init(kvm->nitro.syscall_filter_ht);
}

void nitro_destroy_vm_hook(struct kvm *kvm){
	//deinit nitro
	kvm->nitro.traps = 0;
}

void nitro_create_vcpu_hook(struct kvm_vcpu *vcpu){
  vcpu->nitro.event.present = false;
  init_completion(&(vcpu->nitro.k_wait_cv));
  sema_init(&(vcpu->nitro.n_wait_sem),0);
  INIT_LIST_HEAD(&vcpu->nitro.stack.list);
}

void nitro_destroy_vcpu_hook(struct kvm_vcpu *vcpu){
	struct syscall_stack_item *tmp;
	struct list_head *pos, *n;

	vcpu->nitro.event.present = false;
  // Not sure if this is safe
  complete_all(&(vcpu->nitro.k_wait_cv));

	// destroy vcpu syscall stack
	list_for_each_safe(pos, n, &vcpu->nitro.stack.list)
	{
		tmp = list_entry(pos, struct syscall_stack_item, list);
		list_del(pos);
		kfree(tmp);
	}
}

int nitro_iotcl_num_vms(void){
  struct kvm *kvm;
  int rv = 0;
  
  spin_lock(&kvm_lock);
  list_for_each_entry(kvm, &vm_list, vm_list)
    rv++;
  spin_unlock(&kvm_lock);
  
  return rv;
}

int nitro_iotcl_attach_vcpus(struct kvm *kvm, struct nitro_vcpus *nvcpus){
  int r,i;
  struct kvm_vcpu *v;
  
  mutex_lock(&kvm->lock);
  
  nvcpus->num_vcpus = atomic_read(&kvm->online_vcpus);
  if(unlikely(nvcpus->num_vcpus > NITRO_MAX_VCPUS)){
    goto error_out;
  }
  
  kvm_for_each_vcpu(r, v, kvm){
    nvcpus->ids[r] = v->vcpu_id;
    kvm_get_kvm(kvm);
    nvcpus->fds[r] = create_vcpu_fd(v);
    if(nvcpus->fds[r]<0){
      for(i=r;i>=0;i--){
        nvcpus->ids[i] = 0;
        nvcpus->fds[i] = 0;
        kvm_put_kvm(kvm);
      }
      goto error_out;
    }
  }
  
  mutex_unlock(&kvm->lock);
  return 0;
  
 error_out:
  mutex_unlock(&kvm->lock);
  return -1;
}

int nitro_ioctl_get_event(struct kvm_vcpu *vcpu, struct event *ev){
  int rv;
  
  rv = down_timeout(&(vcpu->nitro.n_wait_sem), 1000);
  printk(KERN_DEBUG "nitro_ioctl_get_event: past down");
  
  if (rv == 0) {
	  ev->direction = vcpu->nitro.event.direction;
	  ev->type = vcpu->nitro.event.type;
	  ev->regs = vcpu->nitro.event.regs;
	  ev->sregs = vcpu->nitro.event.sregs;
  } else {
    printk(KERN_INFO "nitro_ioctl_get_event: returned non-zero value");
  }
  
  return rv;
}

int nitro_ioctl_continue(struct kvm_vcpu *vcpu) {
  printk(KERN_DEBUG "nitro_ioctl_continue: continuing");

	if(completion_done(&(vcpu->nitro.k_wait_cv)))
    return -1;

  vcpu->nitro.cont = NITRO_CONTINUATION_CONTINUE;

	complete(&(vcpu->nitro.k_wait_cv));

	return 0;
}

int nitro_ioctl_continue_step_over(struct kvm_vcpu *vcpu){
  printk(KERN_DEBUG "nitro_ioctl_continue_step_over: stepping over system call invocation");

  if(completion_done(&(vcpu->nitro.k_wait_cv)))
    return -1;

  vcpu->nitro.cont = NITRO_CONTINUATION_STEP_OVER;

  complete(&(vcpu->nitro.k_wait_cv));

  return 0;
}

int nitro_is_trap_set(struct kvm *kvm, uint32_t trap){
  return kvm->nitro.traps & trap;
}
EXPORT_SYMBOL_GPL(nitro_is_trap_set);

int nitro_add_syscall_filter(struct kvm *kvm, uint64_t syscall_nb)
{
	struct syscall_filter_ht_entry *found;
	uint64_t key = syscall_nb;

	found = nitro_find_syscall(kvm, syscall_nb);

	if (!found)
	{
		mutex_lock(&kvm->lock);
		found = kmalloc(sizeof(struct syscall_filter_ht_entry), GFP_KERNEL);
		hash_add(kvm->nitro.syscall_filter_ht, &found->node, key);
		mutex_unlock(&kvm->lock);
	}
	return 0;
}

int nitro_remove_syscall_filter(struct kvm *kvm, uint64_t syscall_nb)
{
	struct syscall_filter_ht_entry *found;

	found = nitro_find_syscall(kvm, syscall_nb);
	if (found)
	{
		mutex_lock(&kvm->lock);
		hash_del(&found->node);
		kfree(found);
		mutex_unlock(&kvm->lock);
	}

	return 0;
}

int nitro_clear_syscall_filter(struct kvm *kvm)
{
	int bkt = 0;
	struct syscall_filter_ht_entry *entry;
	struct hlist_node *tmp;

	mutex_lock(&kvm->lock);
	hash_for_each_safe(kvm->nitro.syscall_filter_ht, bkt, tmp, entry, node)
	{
		hash_del(&entry->node);
		kfree(entry);
	}

	mutex_unlock(&kvm->lock);
	return 0;
}

struct syscall_filter_ht_entry* nitro_find_syscall(struct kvm* kvm, uint64_t syscall_nb)
{
	uint64_t key = syscall_nb;
	struct syscall_filter_ht_entry *found = NULL;

	mutex_lock(&kvm->lock);
	hash_for_each_possible(kvm->nitro.syscall_filter_ht, found, node, key)
	{
		break;
	}
	mutex_unlock(&kvm->lock);

  printk("nitro_find_syscall: %s", found == NULL ? "null" : "not-null");
	return found;
}

