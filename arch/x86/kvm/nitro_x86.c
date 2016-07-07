#include "nitro_x86.h"

#include "x86.h"

#include <linux/nitro_main.h>
#include <linux/kernel.h>
#include <linux/completion.h>

extern int kvm_set_msr_common(struct kvm_vcpu*, struct msr_data*);

static void nitro_set_trap_efer(struct kvm_vcpu* vcpu, bool enabled)
{
    u64 efer;
    struct msr_data msr_info;

    printk(KERN_INFO "setting trap on efer to %d\n", enabled);
    kvm_get_msr_common(vcpu, MSR_EFER, &efer);
    msr_info.index = MSR_EFER;
    if (enabled)
        msr_info.data = efer & ~EFER_SCE;
    else
        msr_info.data = efer | EFER_SCE;
    msr_info.host_initiated = true;
    kvm_set_msr_common(vcpu, &msr_info);

}

int nitro_set_syscall_trap(struct kvm *kvm, bool enabled){
  int i;
  struct kvm_vcpu *vcpu;

  
  printk(KERN_INFO "nitro: set syscall trap\n");
  
  kvm_for_each_vcpu(i, vcpu, kvm){
    vcpu->nitro.event = 0;
    if (enabled)
    {
        kvm->nitro.traps |= NITRO_TRAP_SYSCALL;
        init_completion(&vcpu->nitro.k_wait_cv);
    }
    else
    {
        kvm->nitro.traps &= ~(NITRO_TRAP_SYSCALL);
        complete_all(&(vcpu->nitro.k_wait_cv));
    }

    nitro_vcpu_load(vcpu);

    nitro_set_trap_efer(vcpu, enabled);

    vcpu_put(vcpu);
  }
  
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
  nitro_wait(vcpu);
  
  return 0;
}

int nitro_report_sysret(struct kvm_vcpu *vcpu){

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

