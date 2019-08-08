// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection
 *
 * Copyright (C) 2017-2019 Bitdefender S.R.L.
 *
 */
#include <linux/net.h>
#include "kvmi_int.h"

bool kvmi_sock_get(struct kvmi *ikvm, int fd)
{
	struct socket *sock;
	int r;

	sock = sockfd_lookup(fd, &r);
	if (!sock) {
		kvmi_err(ikvm, "Invalid file handle: %d\n", fd);
		return false;
	}

	ikvm->sock = sock;

	return true;
}

void kvmi_sock_put(struct kvmi *ikvm)
{
	if (ikvm->sock)
		sockfd_put(ikvm->sock);
}

void kvmi_sock_shutdown(struct kvmi *ikvm)
{
	kernel_sock_shutdown(ikvm->sock, SHUT_RDWR);
}

bool kvmi_msg_process(struct kvmi *ikvm)
{
	kvmi_info(ikvm, "TODO: %s", __func__);
	return false;
}
