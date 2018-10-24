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

	up(&(vcpu->nitro.n_wait_sem));
	rv = wait_for_completion_interruptible_timeout(&(vcpu->nitro.k_wait_cv),msecs_to_jiffies(30000));

	if (rv == 0)
		printk(KERN_INFO "nitro: %s: wait timed out\n",__FUNCTION__);
	else if (rv < 0)
		printk(KERN_INFO "nitro: %s: wait interrupted\n",__FUNCTION__);

	return;
}

void nitro_report_event(struct kvm_vcpu *vcpu, uint64_t syscall_nb){
	struct kvm* kvm = vcpu->kvm;

	// if no filter, report all events
	// or if there is a filter
	if (hash_empty(kvm->nitro.syscall_filter_ht) == true
			|| nitro_find_syscall(kvm, syscall_nb))
	{
		nitro_wait(vcpu);
		vcpu->nitro.event.present = false;
	}
}

void nitro_process_event(struct kvm_vcpu *vcpu)
{
	uint64_t syscall_nb = 0;
	struct syscall_stack_item *item= NULL;

	if (vcpu->nitro.event.direction == ENTER)
	{
		syscall_nb = vcpu->nitro.event.regs.rax;
		if (!vcpu->nitro.syscall_stack_counter >= NITRO_SYSCALL_STACK_SIZE)
		{
			vcpu->nitro.syscall_stack[vcpu->nitro.syscall_stack_counter] = syscall_nb;
			vcpu->nitro.syscall_stack_counter++;
		}
		else
			printk(KERN_INFO "enter: syscall enter - stack is full\n");
	}
	else
	{
		// EXIT
		// pop last syscall nb
		// check if not full
		if (!vcpu->nitro.syscall_stack_counter >= NITRO_SYSCALL_STACK_SIZE)
		{
			syscall_nb = vcpu->nitro.syscall_stack[vcpu->nitro.syscall_stack_counter];
		}
		else
		{
			printk(KERN_DEBUG "nitro: syscall exit - stack is full\n");
			vcpu->nitro.event.present = false;
			return;
		}
	}
	nitro_report_event(vcpu, syscall_nb);
}

u64 nitro_get_efer(struct kvm_vcpu *vcpu){
	return nitro_is_trap_set(vcpu->kvm, NITRO_TRAP_SYSCALL) ? (vcpu->arch.efer | EFER_SCE) : vcpu->arch.efer;
}

