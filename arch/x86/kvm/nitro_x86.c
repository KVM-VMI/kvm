#include "nitro_x86.h"

#include "x86.h"

#include <linux/nitro_main.h>

extern int kvm_set_msr_common(struct kvm_vcpu*, struct msr_data*);

int nitro_set_syscall_trap(struct kvm *kvm){
  int i;
  struct kvm_vcpu *vcpu;
  u64 efer;
  struct msr_data msr_info;
  
  printk(KERN_INFO "nitro: set syscall trap\n");
  
  mutex_lock(&kvm->lock);
  
  kvm_for_each_vcpu(i, vcpu, kvm){
    vcpu_load(vcpu);
    kvm_get_msr_common(vcpu, MSR_EFER, &efer);
    msr_info.index = MSR_EFER;
    msr_info.data = efer & ~EFER_SCE;
    msr_info.host_initiated = true;
    kvm_set_msr_common(vcpu, &msr_info);
    vcpu_put(vcpu);
  }
  
  kvm->nitro.trap_syscall = 1;
  
  mutex_unlock(&kvm->lock);
  
  return 0;
}

int nitro_unset_syscall_trap(struct kvm *kvm){
  int i;
  struct kvm_vcpu *vcpu;
  u64 efer;
  struct msr_data msr_info;
  
  printk(KERN_INFO "nitro: unset syscall trap\n");
  
  mutex_lock(&kvm->lock);
  
  kvm->nitro.trap_syscall = 0;
  
  kvm_for_each_vcpu(i, vcpu, kvm){
    vcpu_load(vcpu);
    kvm_get_msr_common(vcpu, MSR_EFER, &efer);
    msr_info.index = MSR_EFER;
    msr_info.data = efer | EFER_SCE;
    msr_info.host_initiated = true;
    kvm_set_msr_common(vcpu, &msr_info);
    //if waiters, wake up
    if(completion_done(&(vcpu->nitro.k_wait_cv)) == 0)
      complete_all(&(vcpu->nitro.k_wait_cv));
    vcpu_put(vcpu);
  }
  
  mutex_unlock(&kvm->lock);

  return 0;
}

int nitro_handle_syscall_trap(struct kvm_vcpu *vcpu){
  //printk(KERN_INFO "nitro: syscall trap\n");
  
  vcpu->nitro.trap_syscall_hit = 0;
  vcpu->nitro.event = KVM_NITRO_SYSCALL_TRAPPED;
  
  up(&(vcpu->nitro.n_wait_sem));
  vcpu_put(vcpu);
  wait_for_completion_killable(&(vcpu->nitro.k_wait_cv));
  vcpu_load(vcpu);

  //returning 0 will give control back to qemu
  return 1;
}

