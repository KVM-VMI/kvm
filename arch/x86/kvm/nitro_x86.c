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
	if (enabled)
	{
		kvm_x86_ops->get_msr(vcpu, &msr_info);
		old_sysenter_cs = msr_info.data;
		printk(KERN_INFO "nitro: old sysenter cs = 0x%llx\n", old_sysenter_cs);
		msr_info.data = 0;
	}
    else
	{
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

void nitro_wait(struct kvm_vcpu *vcpu){
  long rv;
  printk("nitro_wait called");
  
  up(&(vcpu->nitro.n_wait_sem));
  printk("nitro_wait past up(n_wait_sem)");
  rv = wait_for_completion_interruptible_timeout(&(vcpu->nitro.k_wait_cv),msecs_to_jiffies(30000));
  
  if (rv == 0)
    printk(KERN_INFO "nitro: %s: wait timed out\n",__FUNCTION__);
  else if (rv < 0)
    printk(KERN_INFO "nitro: %s: wait interrupted\n",__FUNCTION__);

  // Will break if the event has not been handled with continue
  
  return;
}

void nitro_report_event(struct kvm_vcpu *vcpu, uint64_t syscall_nb){
	struct kvm* kvm = vcpu->kvm;

	// if no filter, report all events
	// or if there is a filter
	/* if (hash_empty(kvm->nitro.syscall_filter_ht) == true */
	/* 		|| nitro_find_syscall(kvm, syscall_nb)) */
	/* { */
	/* 	nitro_wait(vcpu); */
	/* 	vcpu->nitro.event.present = false; */
	/* } */
  nitro_wait(vcpu);
	vcpu->nitro.event.present = false;
}

void nitro_process_event(struct kvm_vcpu *vcpu)
{
  printk(KERN_DEBUG "nitro_process_event called");
  int er;
	uint64_t syscall_nb = 0;
	if (vcpu->nitro.event.direction == ENTER)
	{
    printk("nitro_process_event got ENTER");
		syscall_nb = vcpu->nitro.event.regs.rax;
		// create new syscall stack item
		struct syscall_stack_item *item = kmalloc(sizeof(struct syscall_stack_item), GFP_KERNEL);
		item->syscall_nb = syscall_nb;
		// add it at tail
		list_add_tail(&item->list, &vcpu->nitro.stack.list);
	}
	else
	{
    printk("nitro_process_event got EXIT");
		// EXIT
		// pop last syscall nb
		if (!list_empty(&vcpu->nitro.stack.list))
		{
			// take last entry
			struct syscall_stack_item *item;
			item = list_last_entry(&vcpu->nitro.stack.list, struct syscall_stack_item, list);
			syscall_nb = item->syscall_nb;
			// delete from list
			list_del(&item->list);
			// free item
			kfree(item);
		}
		else
		{
      // FIXME: If we return here we will break the code as we do not emulate the instruction we are on
			printk(KERN_DEBUG "syscall exit without enter, not reporting\n");
      er = emulate_instruction(vcpu, EMULTYPE_TRAP_UD);
      if (er != EMULATE_DONE) {
        printk("nitro_process_event syscall/sysret emulation != EMULATION_DONE");
        kvm_queue_exception(vcpu, UD_VECTOR);
      }
      vcpu->nitro.event.present = false;
			return;
		}
	}
	nitro_report_event(vcpu, syscall_nb);
}

u64 nitro_get_efer(struct kvm_vcpu *vcpu){
  return nitro_is_trap_set(vcpu->kvm, NITRO_TRAP_SYSCALL) ? (vcpu->arch.efer | EFER_SCE) : vcpu->arch.efer;
}

