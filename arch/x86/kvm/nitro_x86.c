#include "nitro_x86.h"

#include "x86.h"

#include <linux/nitro_main.h>
#include <linux/kernel.h>
#include <linux/completion.h>

extern int kvm_set_msr_common(struct kvm_vcpu*, struct msr_data*);
static u64 old_sysenter_cs = 0;

static void nitro_set_trap_sysenter_cs(struct kvm_vcpu* vcpu, bool enabled)
{
  struct msr_data msr_info;

  printk(KERN_INFO "nitro: setting trap on sysenter CS to %d\n", enabled);
	msr_info.index = MSR_IA32_SYSENTER_CS;
	msr_info.host_initiated = true;
	if (enabled) {
    kvm_x86_ops->get_msr(vcpu, &msr_info);
    old_sysenter_cs = msr_info.data;
    printk(KERN_INFO "nitro: old sysenter cs = 0x%llx\n", old_sysenter_cs);
    msr_info.data = 0;
  } else {
    printk(KERN_INFO "nitro: restoring syscenter cs to 0x%llx\n", old_sysenter_cs);
    msr_info.data = old_sysenter_cs;
  }
	kvm_x86_ops->set_msr(vcpu, &msr_info);
}

static void nitro_set_trap_efer(struct kvm_vcpu* vcpu, bool enabled)
{
  struct msr_data msr_info;

  printk(KERN_INFO "nitro: setting trap on efer to %d\n", enabled);
	msr_info.index = MSR_EFER;
	msr_info.host_initiated = true;
	kvm_get_msr_common(vcpu, &msr_info);
  if (enabled)
		msr_info.data &= ~EFER_SCE;
  else
		msr_info.data |= EFER_SCE;
	kvm_set_msr_common(vcpu, &msr_info);
}

u64 nitro_get_old_sysenter_cs(void)
{
  return old_sysenter_cs;
}

int nitro_set_syscall_trap(struct kvm *kvm, bool enabled){
  int i;
  int r;
  struct kvm_vcpu *vcpu;


  printk(KERN_INFO "nitro: set syscall trap\n");

  kvm_for_each_vcpu(i, vcpu, kvm){

	vcpu->nitro.event.present = false;

	if (enabled)
	{
		kvm->nitro.traps |= NITRO_TRAP_SYSCALL;
		init_completion(&vcpu->nitro.k_wait_cv);
		sema_init(&(vcpu->nitro.n_wait_sem),0);
	}
	else
	{
		kvm->nitro.traps &= ~(NITRO_TRAP_SYSCALL);
		complete_all(&(vcpu->nitro.k_wait_cv));
		// release all waiters on nitro_get_event
		up(&(vcpu->nitro.n_wait_sem));
		nitro_clear_syscall_filter(kvm);
	}


	// wait for vcpu_load mutex
	do {
		r = vcpu_load(vcpu);
	} while (r == -EINTR);

	nitro_set_trap_sysenter_cs(vcpu, enabled);
	nitro_set_trap_efer(vcpu, enabled);

	// update exception bitmap
	kvm_x86_ops->update_bp_intercept(vcpu);
	vcpu_put(vcpu);
  }
  return 0;
}

void nitro_do_continue(struct kvm_vcpu *vcpu) {
  char *type;
  long er = emulate_instruction(vcpu, EMULTYPE_TRAP_UD);
  if (unlikely(er != EMULATE_DONE)) {
    switch (er) {
    case EMULATE_DONE: type = "EMULATE_DONE"; break;
    case EMULATE_USER_EXIT: type = "EMULATE_USER_EXIT"; break;
    case EMULATE_FAIL: type = "EMULATE_FAIL"; break;
    default: type = "unknown"; break;
    }
    printk(KERN_DEBUG "nitro_do_continue: emulate_instruction != EMULATION_DONE: %s", type);
    kvm_queue_exception(vcpu, UD_VECTOR);
  }
}
EXPORT_SYMBOL_GPL(nitro_do_continue);

void nitro_do_continue_step_over(struct kvm_vcpu *vcpu) {
  unsigned long rip = kvm_rip_read(vcpu);
  // Both syscall and sysenter are two bytes
  printk(KERN_DEBUG "nitro_do_continue_step_over: original rip: %lu", rip);
  rip += 2; 
  kvm_rip_write(vcpu, rip);
}

void nitro_wait(struct kvm_vcpu *vcpu) {
  printk(KERN_DEBUG "nitro_wait: called");
  
  up(&(vcpu->nitro.n_wait_sem));
  printk(KERN_DEBUG "nitro_wait: past up");

  // Note we do not have a timeout here. Let's be careful.
  wait_for_completion(&(vcpu->nitro.k_wait_cv));
  printk(KERN_DEBUG "nitro_wait: past wait_for_completion");

  if (vcpu->nitro.event.direction == ENTER) {
    if (likely(is_syscall(vcpu) || is_sysenter(vcpu))) {
        switch (vcpu->nitro.cont) {
        case NITRO_CONTINUATION_CONTINUE:
            printk(KERN_DEBUG "nitro_wait: received continue event");
            nitro_do_continue(vcpu);
            break;
        case NITRO_CONTINUATION_STEP_OVER:
            printk(KERN_DEBUG "nitro_wait: received step over event");
            nitro_do_continue_step_over(vcpu);
            break;
        }
    } else {
      printk(KERN_DEBUG "nitro_wait: processing continuation event on an unknown instruction");
    }
  }
}
EXPORT_SYMBOL_GPL(nitro_do_continue_step_over);

bool nitro_should_propagate(struct kvm_vcpu *vcpu) {
  uint64_t syscall_num;
  if (!hash_empty(vcpu->kvm->nitro.syscall_filter_ht)) {
    return nitro_get_syscall_num(vcpu, &syscall_num) && nitro_find_syscall(vcpu->kvm, syscall_num);
  }
  return true;
}
EXPORT_SYMBOL_GPL(nitro_should_propagate);

// Maybe some locking should be in place...
bool nitro_get_syscall_num(struct kvm_vcpu *vcpu, uint64_t *result) {
  uint64_t syscall_nb = 0;
  bool success = true;
  struct syscall_stack_item *item;
  if (vcpu->nitro.event.direction == ENTER) {
    printk(KERN_DEBUG "nitro_get_syscall_num: got ENTER event");
    syscall_nb = vcpu->nitro.event.regs.rax;
    item = kmalloc(sizeof(struct syscall_stack_item), GFP_KERNEL);
    item->syscall_nb = syscall_nb;
    list_add_tail(&item->list, &vcpu->nitro.stack.list);
  } else {
    printk(KERN_DEBUG "nitro_get_syscall_num: got EXIT event");
		if (!list_empty(&vcpu->nitro.stack.list)) {
			item = list_last_entry(&vcpu->nitro.stack.list, struct syscall_stack_item, list);
			syscall_nb = item->syscall_nb;
			list_del(&item->list);
			kfree(item);
		}
		else {
			printk(KERN_DEBUG "nitro_get_syscall_num: syscall exit without enter");
      success = false;
		}
	}
  printk("nitro_get_syscall_num: %llu", syscall_nb);
  *result = syscall_nb;
  return success;
}


u64 nitro_get_efer(struct kvm_vcpu *vcpu) {
  return nitro_is_trap_set(vcpu->kvm, NITRO_TRAP_SYSCALL)
    ? (vcpu->arch.efer | EFER_SCE) : vcpu->arch.efer;
}

