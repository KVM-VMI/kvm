// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection (message handling)
 *
 * Copyright (C) 2017-2020 Bitdefender S.R.L.
 *
 */
#include <linux/net.h>
#include "kvmi_int.h"

typedef int (*kvmi_vm_msg_fct)(struct kvm_introspection *kvmi,
			       const struct kvmi_msg_hdr *msg,
			       const void *req);

static bool is_vm_command(u16 id);

bool kvmi_sock_get(struct kvm_introspection *kvmi, int fd)
{
	struct socket *sock;
	int err;

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		return false;

	kvmi->sock = sock;

	return true;
}

void kvmi_sock_put(struct kvm_introspection *kvmi)
{
	if (kvmi->sock)
		sockfd_put(kvmi->sock);
}

void kvmi_sock_shutdown(struct kvm_introspection *kvmi)
{
	kernel_sock_shutdown(kvmi->sock, SHUT_RDWR);
}

static int handle_sock_rc(int rc, size_t size)
{
	if (unlikely(rc < 0))
		return rc;
	if (unlikely(rc != size))
		return -EPIPE;
	return 0;
}

static int kvmi_sock_read(struct kvm_introspection *kvmi, void *buf,
			  size_t size)
{
	struct kvec vec = { .iov_base = buf, .iov_len = size, };
	struct msghdr m = { };
	int rc;

	rc = kernel_recvmsg(kvmi->sock, &m, &vec, 1, size, MSG_WAITALL);

	return handle_sock_rc(rc, size);
}

static int kvmi_sock_write(struct kvm_introspection *kvmi, struct kvec *vec,
			   size_t n, size_t size)
{
	struct msghdr m = { };
	int rc;

	rc = kernel_sendmsg(kvmi->sock, &m, vec, n, size);

	return handle_sock_rc(rc, size);
}

static int kvmi_msg_reply(struct kvm_introspection *kvmi,
			  const struct kvmi_msg_hdr *msg, int err,
			  const void *rpl, size_t rpl_size)
{
	struct kvmi_error_code ec;
	struct kvmi_msg_hdr h;
	struct kvec vec[3] = {
		{ .iov_base = &h, .iov_len = sizeof(h) },
		{ .iov_base = &ec, .iov_len = sizeof(ec) },
		{ .iov_base = (void *)rpl, .iov_len = rpl_size },
	};
	size_t size = sizeof(h) + sizeof(ec) + (err ? 0 : rpl_size);
	size_t n = ARRAY_SIZE(vec) - (err ? 1 : 0);

	memset(&h, 0, sizeof(h));
	h.id = msg->id;
	h.seq = msg->seq;
	h.size = size - sizeof(h);

	memset(&ec, 0, sizeof(ec));
	ec.err = err;

	return kvmi_sock_write(kvmi, vec, n, size);
}

static int kvmi_msg_vm_reply(struct kvm_introspection *kvmi,
			     const struct kvmi_msg_hdr *msg,
			     int err, const void *rpl,
			     size_t rpl_size)
{
	return kvmi_msg_reply(kvmi, msg, err, rpl, rpl_size);
}

static int handle_get_version(struct kvm_introspection *kvmi,
			      const struct kvmi_msg_hdr *msg, const void *req)
{
	struct kvmi_get_version_reply rpl;

	memset(&rpl, 0, sizeof(rpl));
	rpl.version = kvmi_version();
	rpl.max_msg_size = KVMI_MAX_MSG_SIZE;

	return kvmi_msg_vm_reply(kvmi, msg, 0, &rpl, sizeof(rpl));
}

static int handle_vm_check_command(struct kvm_introspection *kvmi,
				   const struct kvmi_msg_hdr *msg,
				   const void *_req)
{
	const struct kvmi_vm_check_command *req = _req;
	int ec = 0;

	if (req->padding1 || req->padding2)
		ec = -KVM_EINVAL;
	else if (!is_vm_command(req->id))
		ec = -KVM_ENOENT;
	else if (!kvmi_is_command_allowed(kvmi, req->id))
		ec = -KVM_EPERM;

	return kvmi_msg_vm_reply(kvmi, msg, ec, NULL, 0);
}

static int handle_vm_check_event(struct kvm_introspection *kvmi,
				 const struct kvmi_msg_hdr *msg,
				 const void *_req)
{
	const struct kvmi_vm_check_event *req = _req;
	int ec = 0;

	if (req->padding1 || req->padding2)
		ec = -KVM_EINVAL;
	else if (!kvmi_is_known_event(req->id))
		ec = -KVM_ENOENT;
	else if (!kvmi_is_event_allowed(kvmi, req->id))
		ec = -KVM_EPERM;

	return kvmi_msg_vm_reply(kvmi, msg, ec, NULL, 0);
}

/*
 * These commands are executed by the receiving thread.
 */
static kvmi_vm_msg_fct const msg_vm[] = {
	[KVMI_GET_VERSION]      = handle_get_version,
	[KVMI_VM_CHECK_COMMAND] = handle_vm_check_command,
	[KVMI_VM_CHECK_EVENT]   = handle_vm_check_event,
};

static kvmi_vm_msg_fct get_vm_msg_handler(u16 id)
{
	return id < ARRAY_SIZE(msg_vm) ? msg_vm[id] : NULL;
}

static bool is_vm_message(u16 id)
{
	bool is_vm_msg_id = (id & 1) == 0;

	return is_vm_msg_id && !!get_vm_msg_handler(id);
}

static bool is_vm_command(u16 id)
{
	return is_vm_message(id);
}

static struct kvmi_msg_hdr *kvmi_msg_recv(struct kvm_introspection *kvmi)
{
	struct kvmi_msg_hdr *msg;
	int err;

	msg = kvmi_msg_alloc();
	if (!msg)
		goto out;

	err = kvmi_sock_read(kvmi, msg, sizeof(*msg));
	if (err)
		goto out_err;

	if (msg->size) {
		if (msg->size > KVMI_MAX_MSG_SIZE)
			goto out_err;

		err = kvmi_sock_read(kvmi, msg + 1, msg->size);
		if (err)
			goto out_err;
	}

	return msg;

out_err:
	kvmi_msg_free(msg);
out:
	return NULL;
}

static int kvmi_msg_do_vm_cmd(struct kvm_introspection *kvmi,
			      const struct kvmi_msg_hdr *msg)
{
	kvmi_vm_msg_fct fct = get_vm_msg_handler(msg->id);

	return fct(kvmi, msg, msg + 1);
}

static int kvmi_msg_vm_reply_ec(struct kvm_introspection *kvmi,
				const struct kvmi_msg_hdr *msg, int ec)
{
	return kvmi_msg_vm_reply(kvmi, msg, ec, NULL, 0);
}

static int kvmi_msg_handle_vm_cmd(struct kvm_introspection *kvmi,
				  struct kvmi_msg_hdr *msg)
{
	if (!kvmi_is_command_allowed(kvmi, msg->id))
		return kvmi_msg_vm_reply_ec(kvmi, msg, -KVM_EPERM);

	return kvmi_msg_do_vm_cmd(kvmi, msg);
}

bool kvmi_msg_process(struct kvm_introspection *kvmi)
{
	struct kvmi_msg_hdr *msg;
	int err = -1;

	msg = kvmi_msg_recv(kvmi);
	if (!msg)
		goto out;

	if (is_vm_command(msg->id))
		err = kvmi_msg_handle_vm_cmd(kvmi, msg);
	else
		err = kvmi_msg_vm_reply_ec(kvmi, msg, -KVM_ENOSYS);

	kvmi_msg_free(msg);
out:
	return err == 0;
}
