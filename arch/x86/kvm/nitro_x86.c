#include "nitro_x86.h"

#include "x86.h"

#include <linux/nitro_main.h>
#include <linux/kernel.h>
#include <linux/completion.h>

extern int kvm_set_msr_common(struct kvm_vcpu*, struct msr_data*);

int nitro_set_syscall_trap(struct kvm *kvm,unsigned long *bitmap,int system_call_max){
  int i;
  struct kvm_vcpu *vcpu;
  u64 efer;
  struct msr_data msr_info;
  
  printk(KERN_INFO "nitro: set syscall trap\n");
  
  kvm->nitro.system_call_bm = bitmap;
  kvm->nitro.system_call_max = system_call_max;
  
  kvm->nitro.traps |= NITRO_TRAP_SYSCALL;
  
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
  
  kvm->nitro.traps &= ~(NITRO_TRAP_SYSCALL);
  if(kvm->nitro.system_call_bm != NULL){
    kfree(kvm->nitro.system_call_bm);
    kvm->nitro.system_call_bm = NULL;
  }
  kvm->nitro.system_call_max = 0;

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
  struct nitro_syscall_event_ht *ed;
  
  kvm = vcpu->kvm;
  
  if(kvm->nitro.system_call_max > 0){
    syscall_nr = kvm_register_read(vcpu, VCPU_REGS_RAX);
    
    if(syscall_nr > INT_MAX || syscall_nr > kvm->nitro.system_call_max || !test_bit((int)syscall_nr,kvm->nitro.system_call_bm))
      return 0;
  }
  
  ed = kzalloc(sizeof(struct nitro_syscall_event_ht),GFP_KERNEL);
  ed->rsp = vcpu->nitro.syscall_event_rsp;
  ed->cr3 = vcpu->nitro.syscall_event_cr3;
  hash_add(kvm->nitro.system_call_rsp_ht,&ed->ht,ed->rsp);
  
  memset(&vcpu->nitro.event_data,0,sizeof(union event_data));
  vcpu->nitro.event_data.syscall = ed->rsp;

  nitro_wait(vcpu);
  
  return 0;
}

int nitro_report_sysret(struct kvm_vcpu *vcpu){
  struct kvm *kvm;
  struct nitro_syscall_event_ht *ed;
  
  kvm = vcpu->kvm;
  
  hash_for_each_possible(kvm->nitro.system_call_rsp_ht, ed, ht, vcpu->nitro.syscall_event_rsp){
    if((ed->rsp == vcpu->nitro.syscall_event_rsp) && (ed->cr3 == vcpu->nitro.syscall_event_cr3)){
      hash_del(&ed->ht);
      kfree(ed);
      
      memset(&vcpu->nitro.event_data,0,sizeof(union event_data));
      vcpu->nitro.event_data.syscall = vcpu->nitro.syscall_event_rsp;
      
      nitro_wait(vcpu);
      break;
    }
  }
  
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
    case KVM_NITRO_EVENT_SYSRET:
      r = nitro_report_sysret(vcpu);
      break;
    default:
      printk(KERN_INFO "nitro: %s: unknown event encountered (%d)\n",__FUNCTION__,vcpu->nitro.event);
  }
  vcpu->nitro.event = 0;
  return r;
}

inline u64 nitro_get_efer(struct kvm_vcpu *vcpu){
  return nitro_is_trap_set(vcpu->kvm, NITRO_TRAP_SYSCALL) ? (vcpu->arch.efer | EFER_SCE) : vcpu->arch.efer;
}

