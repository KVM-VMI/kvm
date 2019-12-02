// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection
 *
 * Copyright (C) 2017-2019 Bitdefender S.R.L.
 *
 */
#include <linux/net.h>
#include "kvmi_int.h"

#include <trace/events/kvmi.h>

typedef int (*vcpu_reply_fct)(struct kvm_vcpu *vcpu,
			      const struct kvmi_msg_hdr *msg, int err,
			      const void *rpl, size_t rpl_size);

struct kvmi_vcpu_cmd {
	vcpu_reply_fct reply_cb;
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr cmd;
	} *msg;
};

static const char *const msg_IDs[] = {
	[KVMI_CHECK_COMMAND]         = "KVMI_CHECK_COMMAND",
	[KVMI_CHECK_EVENT]           = "KVMI_CHECK_EVENT",
	[KVMI_CONTROL_CMD_RESPONSE]  = "KVMI_CONTROL_CMD_RESPONSE",
	[KVMI_CONTROL_CR]            = "KVMI_CONTROL_CR",
	[KVMI_CONTROL_EVENTS]        = "KVMI_CONTROL_EVENTS",
	[KVMI_CONTROL_MSR]           = "KVMI_CONTROL_MSR",
	[KVMI_CONTROL_SPP]           = "KVMI_CONTROL_SPP",
	[KVMI_CONTROL_VM_EVENTS]     = "KVMI_CONTROL_VM_EVENTS",
	[KVMI_EVENT]                 = "KVMI_EVENT",
	[KVMI_EVENT_REPLY]           = "KVMI_EVENT_REPLY",
	[KVMI_GET_CPUID]             = "KVMI_GET_CPUID",
	[KVMI_GET_GUEST_INFO]        = "KVMI_GET_GUEST_INFO",
	[KVMI_GET_MAP_TOKEN]         = "KVMI_GET_MAP_TOKEN",
	[KVMI_GET_MAX_GFN]           = "KVMI_GET_MAX_GFN",
	[KVMI_GET_MTRR_TYPE]         = "KVMI_GET_MTRR_TYPE",
	[KVMI_GET_PAGE_ACCESS]       = "KVMI_GET_PAGE_ACCESS",
	[KVMI_GET_PAGE_WRITE_BITMAP] = "KVMI_GET_PAGE_WRITE_BITMAP",
	[KVMI_GET_REGISTERS]         = "KVMI_GET_REGISTERS",
	[KVMI_GET_VCPU_INFO]         = "KVMI_GET_VCPU_INFO",
	[KVMI_GET_VERSION]           = "KVMI_GET_VERSION",
	[KVMI_GET_XSAVE]             = "KVMI_GET_XSAVE",
	[KVMI_INJECT_EXCEPTION]      = "KVMI_INJECT_EXCEPTION",
	[KVMI_PAUSE_VCPU]            = "KVMI_PAUSE_VCPU",
	[KVMI_READ_PHYSICAL]         = "KVMI_READ_PHYSICAL",
	[KVMI_SET_PAGE_ACCESS]       = "KVMI_SET_PAGE_ACCESS",
	[KVMI_SET_PAGE_WRITE_BITMAP] = "KVMI_SET_PAGE_WRITE_BITMAP",
	[KVMI_SET_REGISTERS]         = "KVMI_SET_REGISTERS",
	[KVMI_WRITE_PHYSICAL]        = "KVMI_WRITE_PHYSICAL",
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
	trace_kvmi_vm_reply(msg->id, msg->seq, err);

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

int kvmi_msg_vcpu_reply(struct kvm_vcpu *vcpu,
			const struct kvmi_msg_hdr *msg, int err,
			const void *rpl, size_t rpl_size)
{
	trace_kvmi_vcpu_reply(vcpu->vcpu_id, msg->id, msg->seq, err);

	return kvmi_msg_reply(IKVM(vcpu->kvm), msg, err, rpl, rpl_size);
}

int kvmi_msg_vcpu_drop_reply(struct kvm_vcpu *vcpu,
			      const struct kvmi_msg_hdr *msg, int err,
			      const void *rpl, size_t rpl_size)
{
	if (!kvmi_validate_no_reply(IKVM(vcpu->kvm), msg, rpl_size, err))
		return -KVM_EINVAL;

	return 0;
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

static int handle_control_vm_events(struct kvmi *ikvm,
				    const struct kvmi_msg_hdr *msg,
				    const void *_req)
{
	const unsigned long known_events = KVMI_KNOWN_VM_EVENTS;
	const struct kvmi_control_vm_events *req = _req;
	int ec;

	if (req->padding1 || req->padding2)
		ec = -KVM_EINVAL;
	else if (!test_bit(req->event_id, &known_events))
		ec = -KVM_EINVAL;
	else if (!is_event_allowed(ikvm, req->event_id))
		ec = -KVM_EPERM;
	else
		ec = kvmi_cmd_control_vm_events(ikvm, req->event_id,
						req->enable);

	return kvmi_msg_vm_maybe_reply(ikvm, msg, ec, NULL, 0);
}

static int kvmi_get_vcpu(struct kvmi *ikvm, unsigned int vcpu_idx,
			 struct kvm_vcpu **dest)
{
	struct kvm *kvm = ikvm->kvm;
	struct kvm_vcpu *vcpu;

	if (vcpu_idx >= atomic_read(&kvm->online_vcpus))
		return -KVM_EINVAL;

	vcpu = kvm_get_vcpu(kvm, vcpu_idx);
	if (!vcpu)
		return -KVM_EINVAL;

	*dest = vcpu;
	return 0;
}

static bool invalid_page_access(u64 gpa, u64 size)
{
	u64 off = gpa & ~PAGE_MASK;

	return (size == 0 || size > PAGE_SIZE || off + size > PAGE_SIZE);
}

static int handle_read_physical(struct kvmi *ikvm,
				const struct kvmi_msg_hdr *msg,
				const void *_req)
{
	const struct kvmi_read_physical *req = _req;

	if (invalid_page_access(req->gpa, req->size)) {
		int ec = -KVM_EINVAL;

		return kvmi_msg_vm_maybe_reply(ikvm, msg, ec, NULL, 0);
	}

	return kvmi_cmd_read_physical(ikvm->kvm, req->gpa, req->size,
				      kvmi_msg_vm_maybe_reply, msg);
}

static int handle_write_physical(struct kvmi *ikvm,
				 const struct kvmi_msg_hdr *msg,
				 const void *_req)
{
	const struct kvmi_write_physical *req = _req;
	int ec;

	if (msg->size < sizeof(*req) + req->size)
		return -EINVAL;

	if (invalid_page_access(req->gpa, req->size))
		ec = -KVM_EINVAL;
	else
		ec = kvmi_cmd_write_physical(ikvm->kvm, req->gpa,
					     req->size, req->data);

	return kvmi_msg_vm_maybe_reply(ikvm, msg, ec, NULL, 0);
}

static int handle_get_map_token(struct kvmi *ikvm,
				const struct kvmi_msg_hdr *msg,
				const void *_req)
{
	struct kvmi_get_map_token_reply rpl;
	int ec;

	memset(&rpl, 0, sizeof(rpl));
	ec = kvmi_cmd_alloc_token(ikvm->kvm, &rpl.token);

	return kvmi_msg_vm_maybe_reply(ikvm, msg, ec, &rpl, sizeof(rpl));
}

static bool enable_spp(struct kvmi *ikvm)
{
	if (!ikvm->spp.initialized) {
		int err = kvmi_arch_cmd_control_spp(ikvm);

		ikvm->spp.initialized = true;

		if (!err)
			atomic_set(&ikvm->spp.enabled, true);
	}

	return atomic_read(&ikvm->spp.enabled);
}

static int handle_control_spp(struct kvmi *ikvm,
			      const struct kvmi_msg_hdr *msg,
			      const void *_req)
{
	const struct kvmi_control_spp *req = _req;
	int ec;

	if (req->padding1 || req->padding2 || req->padding3)
		ec = -KVM_EINVAL;
	else if (req->enable && enable_spp(ikvm))
		ec = 0;
	else
		ec = -KVM_EOPNOTSUPP;

	return kvmi_msg_vm_maybe_reply(ikvm, msg, ec, NULL, 0);
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

static int handle_get_page_access(struct kvmi *ikvm,
				  const struct kvmi_msg_hdr *msg,
				  const void *req)
{
	struct kvmi_get_page_access_reply *rpl = NULL;
	size_t rpl_size = 0;
	int err, ec;

	ec = kvmi_arch_cmd_get_page_access(ikvm, msg, req, &rpl, &rpl_size);

	err = kvmi_msg_vm_maybe_reply(ikvm, msg, ec, rpl, rpl_size);
	kvmi_msg_free(rpl);
	return err;
}

static int handle_set_page_access(struct kvmi *ikvm,
				  const struct kvmi_msg_hdr *msg,
				  const void *req)
{
	int ec;

	ec = kvmi_arch_cmd_set_page_access(ikvm, msg, req);

	return kvmi_msg_vm_maybe_reply(ikvm, msg, ec, NULL, 0);
}

static int handle_get_page_write_bitmap(struct kvmi *ikvm,
					const struct kvmi_msg_hdr *msg,
					const void *req)
{
	struct kvmi_get_page_write_bitmap_reply *rpl = NULL;
	size_t rpl_size = 0;
	int err, ec;

	ec = kvmi_arch_cmd_get_page_write_bitmap(ikvm, msg, req, &rpl,
						 &rpl_size);

	err = kvmi_msg_vm_maybe_reply(ikvm, msg, ec, rpl, rpl_size);
	kvmi_msg_free(rpl);
	return err;
}

static int handle_set_page_write_bitmap(struct kvmi *ikvm,
					const struct kvmi_msg_hdr *msg,
					const void *req)
{
	int ec;

	ec = kvmi_arch_cmd_set_page_write_bitmap(ikvm, msg, req);

	return kvmi_msg_vm_maybe_reply(ikvm, msg, ec, NULL, 0);
}

static bool invalid_vcpu_hdr(const struct kvmi_vcpu_hdr *hdr)
{
	return hdr->padding1 || hdr->padding2;
}

/*
 * We handle this vCPU command on the receiving thread to make it easier
 * for userspace to implement a 'pause VM' command. Usually, this is done
 * by sending one 'pause vCPU' command for every vCPU. By handling the
 * command here, the userspace can:
 *    - optimize, by not requesting a reply for the first N-1 vCPU's
 *    - consider the VM stopped once it receives the reply
 *      for the last 'pause vCPU' command
 */
static int handle_pause_vcpu(struct kvmi *ikvm,
			     const struct kvmi_msg_hdr *msg,
			     const void *_req)
{
	const struct kvmi_pause_vcpu *req = _req;
	const struct kvmi_vcpu_hdr *cmd;
	struct kvm_vcpu *vcpu = NULL;
	int err;

	if (req->padding1 || req->padding2 || req->padding3) {
		err = -KVM_EINVAL;
		goto reply;
	}

	cmd = (const struct kvmi_vcpu_hdr *) (msg + 1);

	if (invalid_vcpu_hdr(cmd)) {
		err = -KVM_EINVAL;
		goto reply;
	}

	if (!is_event_allowed(ikvm, KVMI_EVENT_PAUSE_VCPU)) {
		err = -KVM_EPERM;

		if (ikvm->cmd_reply_disabled)
			return kvmi_msg_vm_reply(ikvm, msg, err, NULL, 0);

		goto reply;
	}

	err = kvmi_get_vcpu(ikvm, cmd->vcpu, &vcpu);
	if (!err)
		err = kvmi_cmd_pause_vcpu(vcpu, req->wait == 1);

reply:
	return kvmi_msg_vm_maybe_reply(ikvm, msg, err, NULL, 0);
}

static int handle_get_max_gfn(struct kvmi *ikvm,
				const struct kvmi_msg_hdr *msg,
				const void *req)
{
	struct kvmi_get_max_gfn_reply rpl;
	int ec;

	memset(&rpl, 0, sizeof(rpl));
	ec = kvmi_cmd_get_max_gfn(ikvm->kvm, &rpl.gfn);

	return kvmi_msg_vm_maybe_reply(ikvm, msg, ec, &rpl, sizeof(rpl));
}

/*
 * These commands are executed on the receiving thread/worker.
 */
static int(*const msg_vm[])(struct kvmi *, const struct kvmi_msg_hdr *,
			    const void *) = {
	[KVMI_CHECK_COMMAND]         = handle_check_command,
	[KVMI_CHECK_EVENT]           = handle_check_event,
	[KVMI_CONTROL_CMD_RESPONSE]  = handle_control_cmd_response,
	[KVMI_CONTROL_SPP]           = handle_control_spp,
	[KVMI_CONTROL_VM_EVENTS]     = handle_control_vm_events,
	[KVMI_GET_GUEST_INFO]        = handle_get_guest_info,
	[KVMI_GET_MAP_TOKEN]         = handle_get_map_token,
	[KVMI_GET_MAX_GFN]           = handle_get_max_gfn,
	[KVMI_GET_PAGE_ACCESS]       = handle_get_page_access,
	[KVMI_GET_PAGE_WRITE_BITMAP] = handle_get_page_write_bitmap,
	[KVMI_GET_VERSION]           = handle_get_version,
	[KVMI_PAUSE_VCPU]            = handle_pause_vcpu,
	[KVMI_READ_PHYSICAL]         = handle_read_physical,
	[KVMI_SET_PAGE_ACCESS]       = handle_set_page_access,
	[KVMI_SET_PAGE_WRITE_BITMAP] = handle_set_page_write_bitmap,
	[KVMI_WRITE_PHYSICAL]        = handle_write_physical,
};

static int handle_event_reply(struct kvm_vcpu *vcpu,
			      const struct kvmi_msg_hdr *msg, const void *rpl,
			      vcpu_reply_fct reply_cb)
{
	const struct kvmi_event_reply *reply = rpl;
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvmi *ikvm = IKVM(vcpu->kvm);
	struct kvmi_vcpu_reply *expected = &ivcpu->reply;
	size_t useful, received, common;

	trace_kvmi_event_reply(reply->event, msg->seq);

	if (unlikely(msg->seq != expected->seq))
		goto out;

	common = sizeof(struct kvmi_vcpu_hdr) + sizeof(*reply);
	if (unlikely(msg->size < common))
		goto out;

	if (unlikely(reply->padding1 || reply->padding2))
		goto out;

	received = msg->size - common;
	/* Don't accept newer/bigger structures */
	if (unlikely(received > expected->size))
		goto out;

	useful = min(received, expected->size);
	if (useful)
		memcpy(expected->data, reply + 1, useful);

	if (useful < expected->size)
		memset((char *)expected->data + useful, 0,
			expected->size - useful);

	expected->action = reply->action;
	expected->error = 0;

out:

	if (unlikely(expected->error))
		kvmi_err(ikvm, "Invalid event %d/%d reply seq %x/%x size %u min %zu expected %zu padding %u,%u\n",
			 reply->event, reply->action,
			 msg->seq, expected->seq,
			 msg->size, common,
			 common + expected->size,
			 reply->padding1,
			 reply->padding2);

	ivcpu->reply_waiting = false;
	return expected->error;
}

static int handle_get_vcpu_info(struct kvm_vcpu *vcpu,
				const struct kvmi_msg_hdr *msg,
				const void *req, vcpu_reply_fct reply_cb)
{
	struct kvmi_get_vcpu_info_reply rpl;

	memset(&rpl, 0, sizeof(rpl));
	kvmi_arch_cmd_get_vcpu_info(vcpu, &rpl);

	return reply_cb(vcpu, msg, 0, &rpl, sizeof(rpl));
}

static int handle_get_registers(struct kvm_vcpu *vcpu,
				const struct kvmi_msg_hdr *msg,
				const void *req, vcpu_reply_fct reply_cb)
{
	struct kvmi_get_registers_reply *rpl = NULL;
	size_t rpl_size = 0;
	int err, ec;

	ec = kvmi_arch_cmd_get_registers(vcpu, msg, req, &rpl, &rpl_size);

	err = reply_cb(vcpu, msg, ec, rpl, rpl_size);
	kvmi_msg_free(rpl);
	return err;
}

static int handle_set_registers(struct kvm_vcpu *vcpu,
				const struct kvmi_msg_hdr *msg,
				const void *_req,
				vcpu_reply_fct reply_cb)
{
	const struct kvm_regs *regs = _req;
	int err;

	err = kvmi_cmd_set_registers(vcpu, regs);

	return reply_cb(vcpu, msg, err, NULL, 0);
}

static int handle_inject_exception(struct kvm_vcpu *vcpu,
				   const struct kvmi_msg_hdr *msg,
				   const void *_req,
				   vcpu_reply_fct reply_cb)
{
	const struct kvmi_inject_exception *req = _req;
	int ec;

	if (req->padding)
		ec = -KVM_EINVAL;
	else
		ec = kvmi_arch_cmd_inject_exception(vcpu, req->nr,
						    req->has_error,
						    req->error_code,
						    req->address);

	return reply_cb(vcpu, msg, ec, NULL, 0);
}

static int handle_control_events(struct kvm_vcpu *vcpu,
				 const struct kvmi_msg_hdr *msg,
				 const void *_req,
				 vcpu_reply_fct reply_cb)
{
	unsigned long known_events = KVMI_KNOWN_VCPU_EVENTS;
	const struct kvmi_control_events *req = _req;
	struct kvmi *ikvm = IKVM(vcpu->kvm);
	int ec;

	if (req->padding1 || req->padding2)
		ec = -KVM_EINVAL;
	else if (!test_bit(req->event_id, &known_events))
		ec = -KVM_EINVAL;
	else if (!is_event_allowed(ikvm, req->event_id))
		ec = -KVM_EPERM;
	else
		ec = kvmi_cmd_control_events(vcpu, req->event_id, req->enable);

	return reply_cb(vcpu, msg, ec, NULL, 0);
}

static int handle_control_cr(struct kvm_vcpu *vcpu,
			     const struct kvmi_msg_hdr *msg, const void *req,
			     vcpu_reply_fct reply_cb)
{
	int ec;

	ec = kvmi_arch_cmd_control_cr(vcpu, req);

	return reply_cb(vcpu, msg, ec, NULL, 0);
}

static int handle_control_msr(struct kvm_vcpu *vcpu,
			      const struct kvmi_msg_hdr *msg, const void *req,
			      vcpu_reply_fct reply_cb)
{
	int ec;

	ec = kvmi_arch_cmd_control_msr(vcpu, req);

	return reply_cb(vcpu, msg, ec, NULL, 0);
}

static int handle_get_cpuid(struct kvm_vcpu *vcpu,
			    const struct kvmi_msg_hdr *msg,
			    const void *req, vcpu_reply_fct reply_cb)
{
	struct kvmi_get_cpuid_reply rpl;
	int ec;

	memset(&rpl, 0, sizeof(rpl));

	ec = kvmi_arch_cmd_get_cpuid(vcpu, req, &rpl);

	return reply_cb(vcpu, msg, ec, &rpl, sizeof(rpl));
}

static int handle_get_mtrr_type(struct kvm_vcpu *vcpu,
				const struct kvmi_msg_hdr *msg,
				const void *_req, vcpu_reply_fct reply_cb)
{
	const struct kvmi_get_mtrr_type *req = _req;
	struct kvmi_get_mtrr_type_reply rpl;
	int ec;

	memset(&rpl, 0, sizeof(rpl));

	ec = kvmi_arch_cmd_get_mtrr_type(vcpu, req->gpa, &rpl.type);

	return reply_cb(vcpu, msg, ec, &rpl, sizeof(rpl));
}

static int handle_get_xsave(struct kvm_vcpu *vcpu,
			    const struct kvmi_msg_hdr *msg, const void *req,
			    vcpu_reply_fct reply_cb)
{
	struct kvmi_get_xsave_reply *rpl = NULL;
	size_t rpl_size = 0;
	int err, ec;

	ec = kvmi_arch_cmd_get_xsave(vcpu, &rpl, &rpl_size);

	err = reply_cb(vcpu, msg, ec, rpl, rpl_size);
	kvmi_msg_free(rpl);
	return err;
}

/*
 * These commands are executed on the vCPU thread. The receiving thread
 * passes the messages using a newly allocated 'struct kvmi_vcpu_cmd'
 * and signals the vCPU to handle the command (which includes
 * sending back the reply).
 */
static int(*const msg_vcpu[])(struct kvm_vcpu *,
			      const struct kvmi_msg_hdr *, const void *,
			      vcpu_reply_fct) = {
	[KVMI_CONTROL_CR]       = handle_control_cr,
	[KVMI_CONTROL_EVENTS]   = handle_control_events,
	[KVMI_CONTROL_MSR]      = handle_control_msr,
	[KVMI_EVENT_REPLY]      = handle_event_reply,
	[KVMI_GET_CPUID]        = handle_get_cpuid,
	[KVMI_GET_MTRR_TYPE]    = handle_get_mtrr_type,
	[KVMI_GET_REGISTERS]    = handle_get_registers,
	[KVMI_GET_VCPU_INFO]    = handle_get_vcpu_info,
	[KVMI_GET_XSAVE]        = handle_get_xsave,
	[KVMI_INJECT_EXCEPTION] = handle_inject_exception,
	[KVMI_SET_REGISTERS]    = handle_set_registers,
};

static void kvmi_job_vcpu_cmd(struct kvm_vcpu *vcpu, void *_ctx)
{
	const struct kvmi_vcpu_cmd *ctx = _ctx;
	size_t id = ctx->msg->hdr.id;
	int err;

	err = msg_vcpu[id](vcpu, &ctx->msg->hdr, ctx->msg + 1, ctx->reply_cb);

	if (err) {
		struct kvmi *ikvm = IKVM(vcpu->kvm);

		kvmi_err(ikvm,
			 "%s: cmd id: %zu (%s), err: %d\n", __func__,
			 id, id2str(id), err);
		kvmi_sock_shutdown(ikvm);
	}
}

static void kvmi_free_ctx(void *_ctx)
{
	const struct kvmi_vcpu_cmd *ctx = _ctx;

	kvmi_msg_free(ctx->msg);
	kfree(ctx);
}

static int kvmi_msg_queue_to_vcpu(struct kvm_vcpu *vcpu,
				  const struct kvmi_vcpu_cmd *cmd)
{
	return kvmi_add_job(vcpu, kvmi_job_vcpu_cmd, (void *)cmd,
			    kvmi_free_ctx);
}

static bool is_vm_message(u16 id)
{
	return id < ARRAY_SIZE(msg_vm) && !!msg_vm[id];
}

static bool is_vcpu_message(u16 id)
{
	return id < ARRAY_SIZE(msg_vcpu) && !!msg_vcpu[id];
}

static bool is_unsupported_message(u16 id)
{
	bool supported;

	supported = is_known_message(id) &&
			(is_vm_message(id) || is_vcpu_message(id));

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
	trace_kvmi_vm_command(msg->id, msg->seq);

	return msg_vm[msg->id](ikvm, msg, msg + 1);
}

static int kvmi_msg_dispatch_vcpu_job(struct kvmi *ikvm,
				      struct kvmi_vcpu_cmd *job,
				      bool *queued)
{
	struct kvmi_msg_hdr *hdr = &job->msg->hdr;
	struct kvmi_vcpu_hdr *cmd = &job->msg->cmd;
	struct kvm_vcpu *vcpu = NULL;
	int err;

	trace_kvmi_vcpu_command(cmd->vcpu, hdr->id, hdr->seq);

	if (invalid_vcpu_hdr(cmd))
		return -KVM_EINVAL;

	err = kvmi_get_vcpu(ikvm, cmd->vcpu, &vcpu);

	if (!err && vcpu->arch.mp_state == KVM_MP_STATE_UNINITIALIZED)
		err = -KVM_EAGAIN;

	if (err)
		return kvmi_msg_vm_maybe_reply(ikvm, hdr, err, NULL, 0);

	err = kvmi_msg_queue_to_vcpu(vcpu, job);
	if (!err)
		*queued = true;

	return err;
}

static int kvmi_msg_dispatch_vcpu_msg(struct kvmi *ikvm,
				      struct kvmi_msg_hdr *msg,
				      bool *queued)
{
	struct kvmi_vcpu_cmd *job_msg;
	int err;

	job_msg = kzalloc(sizeof(*job_msg), GFP_KERNEL);
	if (!job_msg)
		return -KVM_ENOMEM;

	job_msg->reply_cb = ikvm->cmd_reply_disabled
				? kvmi_msg_vcpu_drop_reply
				: kvmi_msg_vcpu_reply;
	job_msg->msg = (void *)msg;

	err = kvmi_msg_dispatch_vcpu_job(ikvm, job_msg, queued);

	if (!*queued)
		kfree(job_msg);

	return err;
}

static int kvmi_msg_dispatch(struct kvmi *ikvm,
			     struct kvmi_msg_hdr *msg, bool *queued)
{
	int err;

	if (is_vcpu_message(msg->id))
		err = kvmi_msg_dispatch_vcpu_msg(ikvm, msg, queued);
	else
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

static void kvmi_setup_event_common(struct kvmi_event *ev, u32 ev_id,
				    unsigned short vcpu_idx)
{
	memset(ev, 0, sizeof(*ev));

	ev->vcpu = vcpu_idx;
	ev->event = ev_id;
	ev->size = sizeof(*ev);
}

static void kvmi_setup_event(struct kvm_vcpu *vcpu, struct kvmi_event *ev,
			     u32 ev_id)
{
	kvmi_setup_event_common(ev, ev_id, kvm_vcpu_get_idx(vcpu));
	kvmi_arch_setup_event(vcpu, ev);
}

static inline u32 new_seq(struct kvmi *ikvm)
{
	return atomic_inc_return(&ikvm->ev_seq);
}

int kvmi_send_event(struct kvm_vcpu *vcpu, u32 ev_id,
		    void *ev, size_t ev_size,
		    void *rpl, size_t rpl_size, int *action)
{
	struct kvmi_msg_hdr hdr;
	struct kvmi_event common;
	struct kvec vec[] = {
		{.iov_base = &hdr,	.iov_len = sizeof(hdr)	 },
		{.iov_base = &common,	.iov_len = sizeof(common)},
		{.iov_base = ev,	.iov_len = ev_size	 },
	};
	size_t msg_size = sizeof(hdr) + sizeof(common) + ev_size;
	size_t n = ev_size ? ARRAY_SIZE(vec) : ARRAY_SIZE(vec)-1;
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvmi *ikvm = IKVM(vcpu->kvm);
	int err;

	memset(&hdr, 0, sizeof(hdr));
	hdr.id = KVMI_EVENT;
	hdr.seq = new_seq(ikvm);
	hdr.size = msg_size - sizeof(hdr);

	kvmi_setup_event(vcpu, &common, ev_id);

	memset(&ivcpu->reply, 0, sizeof(ivcpu->reply));

	ivcpu->reply.seq = hdr.seq;
	ivcpu->reply.data = rpl;
	ivcpu->reply.size = rpl_size;
	ivcpu->reply.error = -EINTR;

	trace_kvmi_event(vcpu->vcpu_id, common.event, hdr.seq);

	err = kvmi_sock_write(ikvm, vec, n, msg_size);
	if (err)
		goto out;

	ivcpu->reply_waiting = true;
	err = kvmi_run_jobs_and_wait(vcpu);
	if (err)
		goto out;

	err = ivcpu->reply.error;
	if (err)
		goto out;

	kvmi_post_reply(vcpu);
	*action = ivcpu->reply.action;

out:
	if (err)
		kvmi_sock_shutdown(ikvm);
	return err;
}

int kvmi_msg_send_unhook(struct kvmi *ikvm)
{
	struct kvmi_msg_hdr hdr;
	struct kvmi_event common;
	struct kvec vec[] = {
		{.iov_base = &hdr,	.iov_len = sizeof(hdr)	 },
		{.iov_base = &common,	.iov_len = sizeof(common)},
	};
	size_t msg_size = sizeof(hdr) + sizeof(common);
	size_t n = ARRAY_SIZE(vec);

	memset(&hdr, 0, sizeof(hdr));
	hdr.id = KVMI_EVENT;
	hdr.seq = new_seq(ikvm);
	hdr.size = msg_size - sizeof(hdr);

	kvmi_setup_event_common(&common, KVMI_EVENT_UNHOOK, 0);

	trace_kvmi_event(0, common.event, hdr.seq);

	return kvmi_sock_write(ikvm, vec, n, msg_size);
}

u32 kvmi_msg_send_bp(struct kvm_vcpu *vcpu, u64 gpa, u8 insn_len)
{
	struct kvmi_event_breakpoint e;
	int err, action;

	memset(&e, 0, sizeof(e));
	e.gpa = gpa;
	e.insn_len = insn_len;

	err = kvmi_send_event(vcpu, KVMI_EVENT_BREAKPOINT, &e, sizeof(e),
			      NULL, 0, &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	return action;
}

u32 kvmi_msg_send_hypercall(struct kvm_vcpu *vcpu)
{
	int err, action;

	err = kvmi_send_event(vcpu, KVMI_EVENT_HYPERCALL, NULL, 0,
			      NULL, 0, &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	return action;
}

u32 kvmi_msg_send_pf(struct kvm_vcpu *vcpu, u64 gpa, u64 gva, u8 access,
		     bool *singlestep, bool *rep_complete, u64 *ctx_addr,
		     u8 *ctx_data, u32 *ctx_size)
{
	u32 max_ctx_size = *ctx_size;
	struct kvmi_event_pf e;
	struct kvmi_event_pf_reply r;
	int err, action;

	memset(&e, 0, sizeof(e));
	e.gpa = gpa;
	e.gva = gva;
	e.access = access;

	err = kvmi_send_event(vcpu, KVMI_EVENT_PF, &e, sizeof(e),
			      &r, sizeof(r), &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	if (e.padding1 || e.padding2) {
		struct kvmi *ikvm = IKVM(vcpu->kvm);

		kvmi_err(ikvm, "%s: non zero padding %u,%u\n",
			__func__, e.padding1, e.padding2);
		kvmi_sock_shutdown(ikvm);
		return KVMI_EVENT_ACTION_CONTINUE;
	}

	*ctx_size = 0;

	if (r.ctx_size > max_ctx_size) {
		struct kvmi *ikvm = IKVM(vcpu->kvm);

		kvmi_err(ikvm, "%s: ctx_size (recv:%u max:%u)\n",
				__func__, r.ctx_size, max_ctx_size);

		kvmi_sock_shutdown(ikvm);

		*singlestep = false;
		*rep_complete = 0;

		return KVMI_EVENT_ACTION_CONTINUE;
	}

	*singlestep = r.singlestep;
	*rep_complete = r.rep_complete;

	*ctx_size = min_t(u32, r.ctx_size, sizeof(r.ctx_data));
	*ctx_addr = r.ctx_addr;
	if (*ctx_size)
		memcpy(ctx_data, r.ctx_data, *ctx_size);

	return action;
}

u32 kvmi_msg_send_descriptor(struct kvm_vcpu *vcpu, u8 descriptor, u8 write)
{
	struct kvmi_event_descriptor e;
	int err, action;

	memset(&e, 0, sizeof(e));
	e.descriptor = descriptor;
	e.write = write;

	err = kvmi_send_event(vcpu, KVMI_EVENT_DESCRIPTOR, &e, sizeof(e),
			      NULL, 0, &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	return action;
}

u32 kvmi_msg_send_create_vcpu(struct kvm_vcpu *vcpu)
{
	int err, action;

	err = kvmi_send_event(vcpu, KVMI_EVENT_CREATE_VCPU, NULL, 0,
			      NULL, 0, &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	return action;
}

u32 kvmi_msg_send_pause_vcpu(struct kvm_vcpu *vcpu)
{
	int err, action;

	err = kvmi_send_event(vcpu, KVMI_EVENT_PAUSE_VCPU, NULL, 0,
			      NULL, 0, &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	return action;
}
