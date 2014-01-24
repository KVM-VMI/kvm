#include "nitro_x86.h"

#include "x86.h"

#include <linux/nitro_main.h>
#include <linux/kernel.h>
#include <linux/completion.h>

extern int kvm_set_msr_common(struct kvm_vcpu*, struct msr_data*);

int nitro_set_syscall_trap(struct kvm *kvm,unsigned long *bitmap,int max_syscall){
  int i;
  struct kvm_vcpu *vcpu;
  u64 efer;
  struct msr_data msr_info;
  
  printk(KERN_INFO "nitro: set syscall trap\n");
  
  kvm->nitro.syscall_bitmap = bitmap;
  kvm->nitro.max_syscall = max_syscall;
  
  kvm->nitro.trap_syscall = 1;
  
  kvm_for_each_vcpu(i, vcpu, kvm){
    //vcpu_load(vcpu);
    nitro_vcpu_load(vcpu);
    
    kvm_get_msr_common(vcpu, MSR_EFER, &efer);
    msr_info.index = MSR_EFER;
    msr_info.data = efer & ~EFER_SCE;
    msr_info.host_initiated = true;
    kvm_set_msr_common(vcpu, &msr_info);
    
    init_completion(&vcpu->nitro.k_wait_cv);
    
    vcpu_put(vcpu);
  }
  
  return 0;
}

int nitro_unset_syscall_trap(struct kvm *kvm){
  int i;
  struct kvm_vcpu *vcpu;
  u64 efer;
  struct msr_data msr_info;
  
  printk(KERN_INFO "nitro: unset syscall trap\n");
  
  kvm_for_each_vcpu(i, vcpu, kvm){
    //vcpu_load(vcpu);
    
    vcpu->nitro.event = 0;
    //if waiters, wake up
    //if(completion_done(&(vcpu->nitro.k_wait_cv)) == 0)
    complete_all(&(vcpu->nitro.k_wait_cv));
    
    
    nitro_vcpu_load(vcpu);
    
    kvm_get_msr_common(vcpu, MSR_EFER, &efer);
    msr_info.index = MSR_EFER;
    msr_info.data = efer | EFER_SCE;
    msr_info.host_initiated = true;
    kvm_set_msr_common(vcpu, &msr_info);
    

    
    vcpu_put(vcpu);
  }
  
  kvm->nitro.trap_syscall = 0;
  if(kvm->nitro.syscall_bitmap != NULL){
    kfree(kvm->nitro.syscall_bitmap);
    kvm->nitro.syscall_bitmap = NULL;
  }
  kvm->nitro.max_syscall = 0;

  return 0;
}

void nitro_wait(struct kvm_vcpu *vcpu){
  long rv;
  
  up(&(vcpu->nitro.n_wait_sem));
  rv = wait_for_completion_interruptible_timeout(&(vcpu->nitro.k_wait_cv),msecs_to_jiffies(30000));
  
  if (rv == 0)
    printk(KERN_INFO "nitro: %s: wait timed out\n",__FUNCTION__);
  else if (rv < 0)
    printk(KERN_INFO "nitro: %s: wait interrupted\n",__FUNCTION__);
  
  return;
}

int nitro_report_syscall(struct kvm_vcpu *vcpu){
  unsigned long syscall_nr;
  struct kvm *kvm;
  
  kvm = vcpu->kvm;
  
  if(kvm->nitro.max_syscall > 0){
    syscall_nr = kvm_register_read(vcpu, VCPU_REGS_RAX);
    
    if(syscall_nr > INT_MAX || syscall_nr > kvm->nitro.max_syscall || !test_bit((int)syscall_nr,kvm->nitro.syscall_bitmap))
      return 0;
  }

  nitro_wait(vcpu);
  
  return 0;
}

int nitro_report_event(struct kvm_vcpu *vcpu){
  int r;
  
  r = 0;
  
  switch(vcpu->nitro.event){
    case KVM_NITRO_EVENT_ERROR:
      nitro_wait(vcpu);
      break;
    case KVM_NITRO_EVENT_SYSCALL:
      r = nitro_report_syscall(vcpu);
      break;
    default:
      printk(KERN_INFO "nitro: %s: unknown event encountered (%d)\n",__FUNCTION__,vcpu->nitro.event);
  }
  vcpu->nitro.event = 0;
  return r;
}

