/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_KVMI_HOST_H
#define _ASM_X86_KVMI_HOST_H

#include <asm/kvmi.h>

struct kvmi_interception {
	bool restore_interception;
};

struct kvm_vcpu_arch_introspection {
	struct kvm_regs delayed_regs;
	bool have_delayed_regs;
};

struct kvm_arch_introspection {
};

#endif /* _ASM_X86_KVMI_HOST_H */
