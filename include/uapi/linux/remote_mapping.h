/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __UAPI_REMOTE_MAPPING_H__
#define __UAPI_REMOTE_MAPPING_H__

#include <linux/types.h>
#include <linux/ioctl.h>

// device file interface
#define REMOTE_PROC_MAP	_IOW('r', 0x01, int)

// system call interface
struct rmemfds {
	int32_t ctl_fd;
	int32_t mem_fd;
};

// pidfd interface
#define PIDFD_IO_MAGIC	'p'

struct pidfd_mem_map {
	uint64_t address;
	uint64_t offset;
	uint64_t size;
};

struct pidfd_mem_unmap {
	uint64_t offset;
	uint64_t size;
};

#define PIDFD_MEM_MAP	_IOW(PIDFD_IO_MAGIC, 0x01, struct pidfd_mem_map)
#define PIDFD_MEM_UNMAP _IOW(PIDFD_IO_MAGIC, 0x02, struct pidfd_mem_unmap)
#define PIDFD_MEM_LOCK	_IOW(PIDFD_IO_MAGIC, 0x03, int)

#define PIDFD_MEM_REMAP _IOW(PIDFD_IO_MAGIC, 0x04, unsigned long)
// TODO: actually this is not for pidfd, find better names

#endif /* __UAPI_REMOTE_MAPPING_H__ */
