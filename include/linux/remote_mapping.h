/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_REMOTE_MAPPING_H
#define _LINUX_REMOTE_MAPPING_H

#include <linux/sched.h>
#include <uapi/linux/remote_mapping.h>

#ifdef CONFIG_REMOTE_MAPPING

extern int task_remote_map(struct task_struct *task, struct rmemfds *fds);

#else /* CONFIG_REMOTE_MAPPING */

static inline int task_remote_map(struct task_struct *task, struct rmemfds *fds)
{
	return -EINVAL;
}

#endif /* CONFIG_REMOTE_MAPPING */


#endif /* _LINUX_REMOTE_MAPPING_H */
