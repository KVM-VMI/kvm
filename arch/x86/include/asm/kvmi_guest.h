/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVMI_GUEST_H__
#define __KVMI_GUEST_H__

long kvmi_arch_map_hc(struct kvmi_map_mem_token *tknp,
	gpa_t req_gpa, gpa_t map_gpa);
long kvmi_arch_unmap_hc(gpa_t map_gpa);


#endif
