/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>

/*
 * "Clear" an EPT page when EPT violation #VEs are enabled, in which case the
 * suppress #VE bit needs to be set for all unused entries.
 *
 * %rdi	- page
 */
#define VMX_EPT_SUPPRESS_VE_BIT (1ull << 63)

ENTRY(vmx_suppress_ve_clear_page)
	movl $4096/8,%ecx
	movabsq $0x8000000000000000,%rax
	rep stosq
	ret
ENDPROC(vmx_suppress_ve_clear_page)
