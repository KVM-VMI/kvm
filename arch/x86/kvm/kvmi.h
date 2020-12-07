/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_X86_KVM_KVMI_H
#define ARCH_X86_KVM_KVMI_H

int kvmi_arch_cmd_vcpu_get_registers(struct kvm_vcpu *vcpu,
				const struct kvmi_vcpu_get_registers *req,
				struct kvmi_vcpu_get_registers_reply *rpl);
void kvmi_arch_cmd_vcpu_set_registers(struct kvm_vcpu *vcpu,
				      const struct kvm_regs *regs);
int kvmi_arch_cmd_vcpu_control_cr(struct kvm_vcpu *vcpu, int cr, bool enable);

u32 kvmi_msg_send_cr(struct kvm_vcpu *vcpu, u32 cr, u64 old_value,
		     u64 new_value, u64 *ret_value);

#endif
