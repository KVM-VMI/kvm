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

void nitro_create_vm_hook(struct kvm *kvm){
  pid_t pid;
  
  //get current pid
  pid = pid_nr(get_task_pid(current, PIDTYPE_PID));
  printk(KERN_INFO "nitro: new VM created, creating process: %d\n", pid);

  //init nitro
  kvm->nitro.traps = 0;

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
	vcpu->nitro.event.present = false;
	// destroy vcpu syscall stack
	struct syscall_stack_item *tmp;
	struct list_head *pos, *n;
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
  
  if (rv == 0) {
	  ev->direction = vcpu->nitro.event.direction;
	  ev->type = vcpu->nitro.event.type;
	  ev->regs = vcpu->nitro.event.regs;
	  ev->sregs = vcpu->nitro.event.sregs;
  }
  
  return rv;
}

int nitro_ioctl_continue(struct kvm_vcpu *vcpu){

	// if no waiters
	if(completion_done(&(vcpu->nitro.k_wait_cv)))
		return -1;

	complete(&(vcpu->nitro.k_wait_cv));

	return 0;
}

int nitro_is_trap_set(struct kvm *kvm, uint32_t trap){
  return kvm->nitro.traps & trap;
}

int nitro_add_syscall_filter(struct kvm *kvm, uint64_t syscall_nb)
{

	// search if already present
	int i;
	for (i = 0; i < kvm->nitro.syscall_filter_size; i++)
		if (kvm->nitro.syscall_filter[i] == syscall_nb)
			return 0;

	mutex_lock(&kvm->lock);
	// insert
	kvm->nitro.syscall_filter_size++;
	if (kvm->nitro.syscall_filter_size > NITRO_SYSCALL_FILTER_MAX)
	{
		// error, already at max size
		kvm->nitro.syscall_filter_size--;
		return 1;
	}
	int index = kvm->nitro.syscall_filter_size - 1;
	kvm->nitro.syscall_filter[index] = syscall_nb;
	mutex_unlock(&kvm->lock);
	return 0;
}

int nitro_remove_syscall_filter(struct kvm *kvm, uint64_t syscall_nb)
{
	int i;
	bool found = false;
	for (i = 0; i < kvm->nitro.syscall_filter_size; i++)
		if (kvm->nitro.syscall_filter[i] == syscall_nb)
		{
			found = true;
			break;
		}
	if (found == true)
	{
		mutex_lock(&kvm->lock);
		int j;
		for (j = i + 1; j < kvm->nitro.syscall_filter_size; j++)
		{
			// copy
			kvm->nitro.syscall_filter[j-1] = kvm->nitro.syscall_filter[j];
		}
		kvm->nitro.syscall_filter_size--;
		mutex_unlock(&kvm->lock);
	}


	return 0;
}

bool nitro_find_syscall(struct kvm* kvm, uint64_t syscall_nb)
{
	int i;
	for (i = 0; i < kvm->nitro.syscall_filter_size; i++)
		if (kvm->nitro.syscall_filter[i] == syscall_nb)
			return true;

	return false;
}
