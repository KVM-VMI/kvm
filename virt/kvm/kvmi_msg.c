// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection
 *
 * Copyright (C) 2017-2019 Bitdefender S.R.L.
 *
 */
#include <linux/net.h>
#include "kvmi_int.h"

static const char *const msg_IDs[] = {
	[KVMI_CHECK_COMMAND]         = "KVMI_CHECK_COMMAND",
	[KVMI_CHECK_EVENT]           = "KVMI_CHECK_EVENT",
	[KVMI_CONTROL_CMD_RESPONSE]  = "KVMI_CONTROL_CMD_RESPONSE",
	[KVMI_GET_GUEST_INFO]        = "KVMI_GET_GUEST_INFO",
	[KVMI_GET_VERSION]           = "KVMI_GET_VERSION",
};

static bool is_known_message(u16 id)
{
	return id < ARRAY_SIZE(msg_IDs) && msg_IDs[id];
}

static const char *id2str(u16 id)
{
	return is_known_message(id) ? msg_IDs[id] : "unknown";
}

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

static int kvmi_sock_read(struct kvmi *ikvm, void *buf, size_t size)
{
	struct kvec i = {
		.iov_base = buf,
		.iov_len = size,
	};
	struct msghdr m = { };
	int rc;

	rc = kernel_recvmsg(ikvm->sock, &m, &i, 1, size, MSG_WAITALL);

	if (rc > 0)
		print_hex_dump_debug("read: ", DUMP_PREFIX_NONE, 32, 1,
					buf, rc, false);

	if (unlikely(rc != size)) {
		if (rc >= 0)
			rc = -EPIPE;
		else
			kvmi_err(ikvm, "kernel_recvmsg: %d\n", rc);
		return rc;
	}

	return 0;
}

static int kvmi_sock_write(struct kvmi *ikvm, struct kvec *i, size_t n,
			   size_t size)
{
	struct msghdr m = { };
	int rc, k;

	rc = kernel_sendmsg(ikvm->sock, &m, i, n, size);

	if (rc > 0)
		for (k = 0; k < n; k++)
			print_hex_dump_debug("write: ", DUMP_PREFIX_NONE, 32, 1,
					i[k].iov_base, i[k].iov_len, false);

	if (unlikely(rc != size)) {
		kvmi_err(ikvm, "kernel_sendmsg: %d\n", rc);
		if (rc >= 0)
			rc = -EPIPE;
		return rc;
	}

	return 0;
}

static int kvmi_msg_reply(struct kvmi *ikvm,
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
	size_t n = err ? ARRAY_SIZE(vec) - 1 : ARRAY_SIZE(vec);

	memset(&h, 0, sizeof(h));
	h.id = msg->id;
	h.seq = msg->seq;
	h.size = size - sizeof(h);

	memset(&ec, 0, sizeof(ec));
	ec.err = err;

	return kvmi_sock_write(ikvm, vec, n, size);
}

static int kvmi_msg_vm_reply(struct kvmi *ikvm,
			     const struct kvmi_msg_hdr *msg, int err,
			     const void *rpl, size_t rpl_size)
{
	return kvmi_msg_reply(ikvm, msg, err, rpl, rpl_size);
}

static bool kvmi_validate_no_reply(struct kvmi *ikvm,
				   const struct kvmi_msg_hdr *msg,
				   size_t rpl_size, int err)
{
	if (rpl_size) {
		kvmi_err(ikvm, "Reply disabled for command %d", msg->id);
		return false;
	}

	if (err)
		kvmi_warn(ikvm, "Error code %d discarded for message id %d\n",
			  err, msg->id);

	return true;
}

static int kvmi_msg_vm_maybe_reply(struct kvmi *ikvm,
				   const struct kvmi_msg_hdr *msg,
				   int err, const void *rpl,
				   size_t rpl_size)
{
	if (ikvm->cmd_reply_disabled) {
		if (!kvmi_validate_no_reply(ikvm, msg, rpl_size, err))
			return -KVM_EINVAL;
		return 0;
	}

	return kvmi_msg_vm_reply(ikvm, msg, err, rpl, rpl_size);
}

static int handle_get_version(struct kvmi *ikvm,
			      const struct kvmi_msg_hdr *msg, const void *req)
{
	struct kvmi_get_version_reply rpl;

	memset(&rpl, 0, sizeof(rpl));
	rpl.version = KVMI_VERSION;

	return kvmi_msg_vm_maybe_reply(ikvm, msg, 0, &rpl, sizeof(rpl));
}

static bool is_command_allowed(struct kvmi *ikvm, int id)
{
	return test_bit(id, ikvm->cmd_allow_mask);
}

static int handle_check_command(struct kvmi *ikvm,
				const struct kvmi_msg_hdr *msg,
				const void *_req)
{
	const struct kvmi_check_command *req = _req;
	int ec = 0;

	if (req->padding1 || req->padding2)
		ec = -KVM_EINVAL;
	else if (!is_command_allowed(ikvm, req->id))
		ec = -KVM_EPERM;

	return kvmi_msg_vm_maybe_reply(ikvm, msg, ec, NULL, 0);
}

static bool is_event_allowed(struct kvmi *ikvm, int id)
{
	return test_bit(id, ikvm->event_allow_mask);
}

static int handle_check_event(struct kvmi *ikvm,
			      const struct kvmi_msg_hdr *msg, const void *_req)
{
	const struct kvmi_check_event *req = _req;
	int ec = 0;

	if (req->padding1 || req->padding2)
		ec = -KVM_EINVAL;
	else if (!is_event_allowed(ikvm, req->id))
		ec = -KVM_EPERM;

	return kvmi_msg_vm_maybe_reply(ikvm, msg, ec, NULL, 0);
}

static int handle_get_guest_info(struct kvmi *ikvm,
				 const struct kvmi_msg_hdr *msg,
				 const void *req)
{
	struct kvmi_get_guest_info_reply rpl;

	memset(&rpl, 0, sizeof(rpl));
	rpl.vcpu_count = atomic_read(&ikvm->kvm->online_vcpus);

	return kvmi_msg_vm_maybe_reply(ikvm, msg, 0, &rpl, sizeof(rpl));
}

static int handle_control_cmd_response(struct kvmi *ikvm,
					const struct kvmi_msg_hdr *msg,
					const void *_req)
{
	const struct kvmi_control_cmd_response *req = _req;
	bool disabled, now;
	int err;

	if (req->padding1 || req->padding2)
		return -KVM_EINVAL;

	disabled = !req->enable;
	now = (req->now == 1);

	if (now)
		ikvm->cmd_reply_disabled = disabled;

	err = kvmi_msg_vm_maybe_reply(ikvm, msg, 0, NULL, 0);

	if (!now)
		ikvm->cmd_reply_disabled = disabled;

	return err;
}

/*
 * These commands are executed on the receiving thread/worker.
 */
static int(*const msg_vm[])(struct kvmi *, const struct kvmi_msg_hdr *,
			    const void *) = {
	[KVMI_CHECK_COMMAND]         = handle_check_command,
	[KVMI_CHECK_EVENT]           = handle_check_event,
	[KVMI_CONTROL_CMD_RESPONSE]  = handle_control_cmd_response,
	[KVMI_GET_GUEST_INFO]        = handle_get_guest_info,
	[KVMI_GET_VERSION]           = handle_get_version,
};

static bool is_vm_message(u16 id)
{
	return id < ARRAY_SIZE(msg_vm) && !!msg_vm[id];
}

static bool is_unsupported_message(u16 id)
{
	bool supported;

	supported = is_known_message(id) && is_vm_message(id);

	return !supported;
}

static int kvmi_consume_bytes(struct kvmi *ikvm, size_t bytes)
{
	size_t to_read;
	u8 buf[1024];
	int err = 0;

	while (bytes && !err) {
		to_read = min(bytes, sizeof(buf));

		err = kvmi_sock_read(ikvm, buf, to_read);

		bytes -= to_read;
	}

	return err;
}

static struct kvmi_msg_hdr *kvmi_msg_recv(struct kvmi *ikvm, bool *unsupported)
{
	struct kvmi_msg_hdr *msg;
	int err;

	*unsupported = false;

	msg = kvmi_msg_alloc();
	if (!msg)
		goto out_err;

	err = kvmi_sock_read(ikvm, msg, sizeof(*msg));
	if (err)
		goto out_err;

	if (msg->size > KVMI_MSG_SIZE)
		goto out_err_msg;

	if (is_unsupported_message(msg->id)) {
		if (msg->size && kvmi_consume_bytes(ikvm, msg->size) < 0)
			goto out_err_msg;

		*unsupported = true;
		return msg;
	}

	if (msg->size && kvmi_sock_read(ikvm, msg + 1, msg->size) < 0)
		goto out_err_msg;

	return msg;

out_err_msg:
	kvmi_err(ikvm, "%s id %u (%s) size %u\n",
		 __func__, msg->id, id2str(msg->id), msg->size);

out_err:
	kvmi_msg_free(msg);

	return NULL;
}

static int kvmi_msg_dispatch_vm_cmd(struct kvmi *ikvm,
				    const struct kvmi_msg_hdr *msg)
{
	return msg_vm[msg->id](ikvm, msg, msg + 1);
}

static int kvmi_msg_dispatch(struct kvmi *ikvm,
			     struct kvmi_msg_hdr *msg, bool *queued)
{
	int err;

	err = kvmi_msg_dispatch_vm_cmd(ikvm, msg);

	if (err)
		kvmi_err(ikvm, "%s: msg id: %u (%s), err: %d\n", __func__,
			 msg->id, id2str(msg->id), err);

	return err;
}

static bool is_message_allowed(struct kvmi *ikvm, __u16 id)
{
	if (id == KVMI_EVENT_REPLY)
		return true;

	/*
	 * Some commands (eg.pause) request events that might be
	 * disallowed. The command is allowed here, but the function
	 * handling the command will return -KVM_EPERM if the event
	 * is disallowed.
	 */
	return is_command_allowed(ikvm, id);
}

bool kvmi_msg_process(struct kvmi *ikvm)
{
	struct kvmi_msg_hdr *msg;
	bool queued = false;
	bool unsupported;
	int err = -1;

	msg = kvmi_msg_recv(ikvm, &unsupported);
	if (!msg)
		goto out;

	if (unsupported) {
		err = kvmi_msg_vm_reply(ikvm, msg, -KVM_EOPNOTSUPP, NULL, 0);
		goto out;
	}

	if (!is_message_allowed(ikvm, msg->id)) {
		err = kvmi_msg_vm_reply(ikvm, msg, -KVM_EPERM, NULL, 0);
		goto out;
	}

	err = kvmi_msg_dispatch(ikvm, msg, &queued);

out:
	if (!queued)
		kvmi_msg_free(msg);

	return err == 0;
}
