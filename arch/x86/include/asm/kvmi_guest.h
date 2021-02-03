/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVMI_GUEST_H__
#define __KVMI_GUEST_H__

long kvmi_arch_guest_start(void *request);
long kvmi_arch_guest_map(struct kvmi_map_mem_token *token, void *request);
long kvmi_arch_guest_unmap(void *request);
long kvmi_arch_guest_end(void *request);

#endif /* __KVMI_GUEST_H__ */
