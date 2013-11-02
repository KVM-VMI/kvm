#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/compiler.h>
#include <asm/current.h>
#include <asm-generic/errno-base.h>

#include <linux/kvm_host.h>

#include <linux/nitro_main.h>

DEFINE_RAW_SPINLOCK(nitro_vm_lock);
LIST_HEAD(nitro_vm_list);

extern int create_vcpu_fd(struct kvm_vcpu*);

struct nitro_kvm_s* nitro_get_vm_by_creator(pid_t creator){
  struct nitro_kvm_s *rv;
  struct nitro_kvm_s *nitro_kvm;
  
  rv = NULL;
  
  raw_spin_lock(&nitro_vm_lock);
  list_for_each_entry(nitro_kvm,&nitro_vm_list,list)
    if(nitro_kvm->creator == creator){
      rv = nitro_kvm;
      break;
    }
  raw_spin_unlock(&nitro_vm_lock);
  
  return rv;
}

inline struct nitro_kvm_s* nitro_get_vm_by_kvm(struct kvm *kvm){
  return kvm->nitro_kvm;
}

void nitro_create_vm_hook(struct kvm *kvm){
  pid_t pid;
  struct nitro_kvm_s *nitro_kvm;
  
  //get current pid
  pid = pid_nr(get_task_pid(current, PIDTYPE_PID));
  printk(KERN_INFO "nitro: new VM created, creating process: %d\n", pid);
  
  //allocate memory
  nitro_kvm = (struct nitro_kvm_s*) kzalloc(sizeof(struct nitro_kvm_s),GFP_KERNEL);
  //add nitro_kvm to kvm
  kvm->nitro_kvm = nitro_kvm;
  if(nitro_kvm == NULL){
    printk(KERN_WARNING "nitro: unable to alocate memory for nitro_kvm, this VM (%d) will not be added to nitro's list\n", pid);
    return;
  }
  
  //init nitro_kvm
  nitro_kvm->creator = pid;
  nitro_kvm->kvm = kvm;
  
  //add to global list
  raw_spin_lock(&nitro_vm_lock);
  list_add(&nitro_kvm->list,&nitro_vm_list);
  raw_spin_unlock(&nitro_vm_lock);
}

void nitro_destroy_vm_hook(struct kvm *kvm){
  struct nitro_kvm_s *nitro_kvm;
  
  nitro_kvm = nitro_get_vm_by_kvm(kvm);
  
  //remove from global list
  raw_spin_lock(&nitro_vm_lock);
  list_del(&nitro_kvm->list);
  raw_spin_unlock(&nitro_vm_lock);
  
  kvm->nitro_kvm = NULL;
  
  kfree(nitro_kvm);
}

int nitro_iotcl_num_vms(void){
  struct kvm *kvm;
  int rv = 0;
  
  raw_spin_lock(&kvm_lock);
  list_for_each_entry(kvm, &vm_list, vm_list)
    rv++;
  raw_spin_unlock(&kvm_lock);
  
  return rv;
}

int nitro_iotcl_attach_vcpus(struct kvm *kvm, struct nitro_vcpus *nvcpus){
  int r;
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
      kvm_put_kvm(kvm);//this will have to be cleaned up
      goto error_out;
    }
  }
  
  mutex_unlock(&kvm->lock);
  return 0;
  
  error_out:
  mutex_unlock(&kvm->lock);
  return -1;
}



