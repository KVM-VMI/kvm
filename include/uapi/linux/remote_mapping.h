/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __UAPI_REMOTE_MAPPING_H__
#define __UAPI_REMOTE_MAPPING_H__

#include <linux/types.h>
#include <linux/ioctl.h>

struct remote_map_request {
	__u32 req_pid;
	__u64 req_hva;
	__u64 map_hva;
};

#define REMOTE_MAP       _IOW('r', 0x01, struct remote_map_request)
#define REMOTE_UNMAP     _IOW('r', 0x02, unsigned long)

#endif /* __UAPI_REMOTE_MAPPING_H__ */
