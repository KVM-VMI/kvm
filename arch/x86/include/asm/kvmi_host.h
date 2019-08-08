/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_KVMI_HOST_H
#define _ASM_X86_KVMI_HOST_H

#include <asm/kvm_host.h>
#include <asm/kvm_page_track.h>

struct kvmi_arch_mem_access {
	unsigned long active[KVM_PAGE_TRACK_MAX][BITS_TO_LONGS(KVM_MEM_SLOTS_NUM)];
};

#endif /* _ASM_X86_KVMI_HOST_H */
