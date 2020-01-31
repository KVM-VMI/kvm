// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection (message handling)
 *
 * Copyright (C) 2017-2020 Bitdefender S.R.L.
 *
 */
#include <linux/net.h>
#include "kvmi_int.h"

struct kvmi_vcpu_cmd_job {
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr cmd;
	} *msg;
	struct kvm_vcpu *vcpu;
};

static const char *const msg_IDs[] = {
	[KVMI_EVENT_REPLY]         = "KVMI_EVENT_REPLY",
	[KVMI_GET_VERSION]         = "KVMI_GET_VERSION",
	[KVMI_VM_CHECK_COMMAND]    = "KVMI_VM_CHECK_COMMAND",
	[KVMI_VM_CHECK_EVENT]      = "KVMI_VM_CHECK_EVENT",
	[KVMI_VM_CONTROL_EVENTS]   = "KVMI_VM_CONTROL_EVENTS",
	[KVMI_VM_GET_INFO]         = "KVMI_VM_GET_INFO",
	[KVMI_VM_READ_PHYSICAL]    = "KVMI_VM_READ_PHYSICAL",
	[KVMI_VM_WRITE_PHYSICAL]   = "KVMI_VM_WRITE_PHYSICAL",
	[KVMI_VCPU_CONTROL_CR]     = "KVMI_VCPU_CONTROL_CR",
	[KVMI_VCPU_CONTROL_EVENTS] = "KVMI_VCPU_CONTROL_EVENTS",
	[KVMI_VCPU_GET_CPUID]      = "KVMI_VCPU_GET_CPUID",
	[KVMI_VCPU_GET_INFO]       = "KVMI_VCPU_GET_INFO",
	[KVMI_VCPU_GET_REGISTERS]  = "KVMI_VCPU_GET_REGISTERS",
	[KVMI_VCPU_PAUSE]          = "KVMI_VCPU_PAUSE",
	[KVMI_VCPU_SET_REGISTERS]  = "KVMI_VCPU_SET_REGISTERS",
};

static bool is_known_message(u16 id)
{
	return id < ARRAY_SIZE(msg_IDs) && msg_IDs[id];
}

static const char *id2str(u16 id)
{
	return is_known_message(id) ? msg_IDs[id] : "unknown";
}

bool kvmi_sock_get(struct kvm_introspection *kvmi, int fd)
{
	struct socket *sock;
	int r;

	sock = sockfd_lookup(fd, &r);
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

static int kvmi_sock_read(struct kvm_introspection *kvmi, void *buf,
			  size_t size)
{
	struct kvec i = {
		.iov_base = buf,
		.iov_len = size,
	};
	struct msghdr m = { };
	int rc;

	rc = kernel_recvmsg(kvmi->sock, &m, &i, 1, size, MSG_WAITALL);

	if (unlikely(rc != size && rc >= 0))
		rc = -EPIPE;

	return rc >= 0 ? 0 : rc;
}

static int kvmi_sock_write(struct kvm_introspection *kvmi, struct kvec *i,
			   size_t n, size_t size)
{
	struct msghdr m = { };
	int rc;

	rc = kernel_sendmsg(kvmi->sock, &m, i, n, size);

	if (unlikely(rc != size && rc >= 0))
		rc = -EPIPE;

	return rc >= 0 ? 0 : rc;
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
	size_t n = err ? ARRAY_SIZE(vec) - 1 : ARRAY_SIZE(vec);

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

static int kvmi_msg_vcpu_reply(const struct kvmi_vcpu_cmd_job *job,
				const struct kvmi_msg_hdr *msg, int err,
				const void *rpl, size_t rpl_size)
{
	struct kvm_introspection *kvmi = KVMI(job->vcpu->kvm);

	return kvmi_msg_reply(kvmi, msg, err, rpl, rpl_size);
}

static bool is_command_allowed(struct kvm_introspection *kvmi, int id)
{
	return test_bit(id, kvmi->cmd_allow_mask);
}

static bool invalid_vcpu_hdr(const struct kvmi_vcpu_hdr *hdr)
{
	return hdr->padding1 || hdr->padding2;
}

static int kvmi_get_vcpu(struct kvm_introspection *kvmi, unsigned int vcpu_idx,
			 struct kvm_vcpu **dest)
{
	struct kvm *kvm = kvmi->kvm;
	struct kvm_vcpu *vcpu;

	if (vcpu_idx >= atomic_read(&kvm->online_vcpus))
		return -KVM_EINVAL;

	vcpu = kvm_get_vcpu(kvm, vcpu_idx);
	if (!vcpu)
		return -KVM_EINVAL;

	*dest = vcpu;
	return 0;
}

static int handle_get_version(struct kvm_introspection *kvmi,
			      const struct kvmi_msg_hdr *msg, const void *req)
{
	struct kvmi_get_version_reply rpl;

	memset(&rpl, 0, sizeof(rpl));
	rpl.version = KVMI_VERSION;

	return kvmi_msg_vm_reply(kvmi, msg, 0, &rpl, sizeof(rpl));
}

static int handle_check_command(struct kvm_introspection *kvmi,
				const struct kvmi_msg_hdr *msg,
				const void *_req)
{
	const struct kvmi_vm_check_command *req = _req;
	int ec = 0;

	if (req->padding1 || req->padding2)
		ec = -KVM_EINVAL;
	else if (req->id >= KVMI_NUM_COMMANDS)
		ec = -KVM_EINVAL;
	else if (!is_command_allowed(kvmi, req->id))
		ec = -KVM_EPERM;

	return kvmi_msg_vm_reply(kvmi, msg, ec, NULL, 0);
}

static bool is_event_allowed(struct kvm_introspection *kvmi, int id)
{
	return test_bit(id, kvmi->event_allow_mask);
}

static int handle_check_event(struct kvm_introspection *kvmi,
			      const struct kvmi_msg_hdr *msg, const void *_req)
{
	const struct kvmi_vm_check_event *req = _req;
	int ec = 0;

	if (req->padding1 || req->padding2)
		ec = -KVM_EINVAL;
	else if (req->id >= KVMI_NUM_EVENTS)
		ec = -KVM_EINVAL;
	else if (!is_event_allowed(kvmi, req->id))
		ec = -KVM_EPERM;

	return kvmi_msg_vm_reply(kvmi, msg, ec, NULL, 0);
}

static int handle_get_info(struct kvm_introspection *kvmi,
			   const struct kvmi_msg_hdr *msg,
			   const void *req)
{
	struct kvmi_vm_get_info_reply rpl;

	memset(&rpl, 0, sizeof(rpl));
	rpl.vcpu_count = atomic_read(&kvmi->kvm->online_vcpus);

	return kvmi_msg_vm_reply(kvmi, msg, 0, &rpl, sizeof(rpl));
}

static int handle_vm_control_events(struct kvm_introspection *kvmi,
				    const struct kvmi_msg_hdr *msg,
				    const void *_req)
{
	const struct kvmi_vm_control_events *req = _req;
	DECLARE_BITMAP(known_events, KVMI_NUM_EVENTS);
	int ec;

	bitmap_from_u64(known_events, KVMI_KNOWN_VM_EVENTS);

	if (req->padding1 || req->padding2)
		ec = -KVM_EINVAL;
	else if (req->event_id >= KVMI_NUM_EVENTS)
		ec = -KVM_EINVAL;
	else if (!test_bit(req->event_id, known_events))
		ec = -KVM_EINVAL;
	else if (!is_event_allowed(kvmi, req->event_id))
		ec = -KVM_EPERM;
	else
		ec = kvmi_cmd_vm_control_events(kvmi, req->event_id,
						req->enable);

	return kvmi_msg_vm_reply(kvmi, msg, ec, NULL, 0);
}

static bool invalid_page_access(u64 gpa, u64 size)
{
	u64 off = gpa & ~PAGE_MASK;

	return (size == 0 || size > PAGE_SIZE || off + size > PAGE_SIZE);
}

static int handle_read_physical(struct kvm_introspection *kvmi,
				const struct kvmi_msg_hdr *msg,
				const void *_req)
{
	const struct kvmi_vm_read_physical *req = _req;

	if (invalid_page_access(req->gpa, req->size)) {
		int ec = -KVM_EINVAL;

		return kvmi_msg_vm_reply(kvmi, msg, ec, NULL, 0);
	}

	return kvmi_cmd_read_physical(kvmi->kvm, req->gpa, req->size,
				      kvmi_msg_vm_reply, msg);
}

static int handle_write_physical(struct kvm_introspection *kvmi,
				 const struct kvmi_msg_hdr *msg,
				 const void *_req)
{
	const struct kvmi_vm_write_physical *req = _req;
	int ec;

	if (msg->size < sizeof(*req) + req->size)
		return -EINVAL;

	if (invalid_page_access(req->gpa, req->size))
		ec = -KVM_EINVAL;
	else
		ec = kvmi_cmd_write_physical(kvmi->kvm, req->gpa,
					     req->size, req->data);

	return kvmi_msg_vm_reply(kvmi, msg, ec, NULL, 0);
}

/*
 * We handle this vCPU command on the receiving thread to make it easier
 * for userspace to implement a 'pause VM' command. Usually, this is done
 * by sending one 'pause vCPU' command for every vCPU. By handling the
 * command here, the userspace can consider that the VM has stopped
 * once it receives the reply for the last 'pause vCPU' command.
 */
static int handle_pause_vcpu(struct kvm_introspection *kvmi,
			     const struct kvmi_msg_hdr *msg,
			     const void *_req)
{
	const struct kvmi_vcpu_pause *req = _req;
	const struct kvmi_vcpu_hdr *cmd;
	struct kvm_vcpu *vcpu = NULL;
	int err;

	if (req->padding1 || req->padding2 || req->padding3)
		return -KVM_EINVAL;

	if (!is_event_allowed(kvmi, KVMI_EVENT_PAUSE_VCPU))
		return -KVM_EPERM;

	cmd = (const struct kvmi_vcpu_hdr *) (msg + 1);

	if (invalid_vcpu_hdr(cmd)) {
		err = -KVM_EINVAL;
		goto reply;
	}

	err = kvmi_get_vcpu(kvmi, cmd->vcpu, &vcpu);
	if (!err)
		err = kvmi_cmd_vcpu_pause(vcpu, req->wait == 1);

reply:
	return kvmi_msg_vm_reply(kvmi, msg, err, NULL, 0);
}

/*
 * These commands are executed by the receiving thread/worker.
 */
static int(*const msg_vm[])(struct kvm_introspection *,
			    const struct kvmi_msg_hdr *, const void *) = {
	[KVMI_GET_VERSION]       = handle_get_version,
	[KVMI_VM_CHECK_COMMAND]  = handle_check_command,
	[KVMI_VM_CHECK_EVENT]    = handle_check_event,
	[KVMI_VM_CONTROL_EVENTS] = handle_vm_control_events,
	[KVMI_VM_GET_INFO]       = handle_get_info,
	[KVMI_VM_READ_PHYSICAL]  = handle_read_physical,
	[KVMI_VM_WRITE_PHYSICAL] = handle_write_physical,
	[KVMI_VCPU_PAUSE]        = handle_pause_vcpu,
};

static int handle_get_vcpu_info(const struct kvmi_vcpu_cmd_job *job,
				const struct kvmi_msg_hdr *msg,
				const void *req)
{
	struct kvmi_vcpu_get_info_reply rpl;

	memset(&rpl, 0, sizeof(rpl));
	kvmi_arch_cmd_vcpu_get_info(job->vcpu, &rpl);

	return kvmi_msg_vcpu_reply(job, msg, 0, &rpl, sizeof(rpl));
}

static int handle_event_reply(const struct kvmi_vcpu_cmd_job *job,
			      const struct kvmi_msg_hdr *msg, const void *rpl)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(job->vcpu);
	struct kvm_introspection *kvmi = KVMI(job->vcpu->kvm);
	struct kvmi_vcpu_reply *expected = &vcpui->reply;
	const struct kvmi_event_reply *reply = rpl;
	size_t useful, received, common;

	if (unlikely(msg->seq != expected->seq))
		goto out_wakeup;

	common = sizeof(struct kvmi_vcpu_hdr) + sizeof(*reply);
	if (unlikely(msg->size < common))
		goto out_wakeup;

	if (unlikely(reply->padding1 || reply->padding2))
		goto out_wakeup;

	received = msg->size - common;
	/* Don't accept newer/bigger structures */
	if (unlikely(received > expected->size))
		goto out_wakeup;

	useful = min(received, expected->size);
	if (useful)
		memcpy(expected->data, reply + 1, useful);

	if (useful < expected->size)
		memset((char *)expected->data + useful, 0,
			expected->size - useful);

	expected->action = reply->action;
	expected->error = 0;

out_wakeup:

	if (unlikely(expected->error))
		kvmi_err(kvmi, "Invalid event %d/%d reply seq %x/%x size %u min %zu expected %zu padding %u,%u\n",
			 reply->event, reply->action,
			 msg->seq, expected->seq,
			 msg->size, common,
			 common + expected->size,
			 reply->padding1,
			 reply->padding2);

	vcpui->waiting_for_reply = false;
	return expected->error;
}

static int handle_vcpu_control_events(const struct kvmi_vcpu_cmd_job *job,
				      const struct kvmi_msg_hdr *msg,
				      const void *_req)
{
	struct kvm_introspection *kvmi = KVMI(job->vcpu->kvm);
	const struct kvmi_vcpu_control_events *req = _req;
	DECLARE_BITMAP(known_events, KVMI_NUM_EVENTS);
	int ec;

	bitmap_from_u64(known_events, KVMI_KNOWN_VCPU_EVENTS);

	if (req->padding1 || req->padding2)
		ec = -KVM_EINVAL;
	else if (req->event_id >= KVMI_NUM_EVENTS)
		ec = -KVM_EINVAL;
	else if (!test_bit(req->event_id, known_events))
		ec = -KVM_EINVAL;
	else if (!is_event_allowed(kvmi, req->event_id))
		ec = -KVM_EPERM;
	else {
		ec = kvmi_cmd_vcpu_control_events(job->vcpu, req->event_id,
						  req->enable);
		if (ec)
			ec = -KVM_EOPNOTSUPP;
	}

	return kvmi_msg_vcpu_reply(job, msg, ec, NULL, 0);
}

static int handle_get_registers(const struct kvmi_vcpu_cmd_job *job,
				const struct kvmi_msg_hdr *msg,
				const void *req)
{
	struct kvmi_vcpu_get_registers_reply *rpl = NULL;
	size_t rpl_size = 0;
	int err, ec;

	ec = kvmi_arch_cmd_vcpu_get_registers(job->vcpu, msg, req,
					      &rpl, &rpl_size);

	err = kvmi_msg_vcpu_reply(job, msg, ec, rpl, rpl_size);
	kvmi_msg_free(rpl);
	return err;
}

static int handle_set_registers(const struct kvmi_vcpu_cmd_job *job,
				const struct kvmi_msg_hdr *msg,
				const void *_req)
{
	const struct kvm_regs *regs = _req;
	int ec;

	ec = kvmi_cmd_vcpu_set_registers(job->vcpu, regs);

	return kvmi_msg_vcpu_reply(job, msg, ec, NULL, 0);
}

static int handle_get_cpuid(const struct kvmi_vcpu_cmd_job *job,
			    const struct kvmi_msg_hdr *msg,
			    const void *req)
{
	struct kvmi_vcpu_get_cpuid_reply rpl;
	int ec;

	memset(&rpl, 0, sizeof(rpl));

	ec = kvmi_arch_cmd_vcpu_get_cpuid(job->vcpu, req, &rpl);

	return kvmi_msg_vcpu_reply(job, msg, ec, &rpl, sizeof(rpl));
}

static int handle_vcpu_control_cr(const struct kvmi_vcpu_cmd_job *job,
				  const struct kvmi_msg_hdr *msg,
				  const void *req)
{
	int ec;

	ec = kvmi_arch_cmd_vcpu_control_cr(job->vcpu, req);

	return kvmi_msg_vcpu_reply(job, msg, ec, NULL, 0);
}

/*
 * These commands are executed on the vCPU thread. The receiving thread
 * passes the messages using a newly allocated 'struct kvmi_vcpu_cmd_job'
 * and signals the vCPU to handle the command (which includes
 * sending back the reply).
 */
static int(*const msg_vcpu[])(const struct kvmi_vcpu_cmd_job *,
			      const struct kvmi_msg_hdr *, const void *) = {
	[KVMI_EVENT_REPLY]         = handle_event_reply,
	[KVMI_VCPU_CONTROL_CR]     = handle_vcpu_control_cr,
	[KVMI_VCPU_CONTROL_EVENTS] = handle_vcpu_control_events,
	[KVMI_VCPU_GET_CPUID]      = handle_get_cpuid,
	[KVMI_VCPU_GET_INFO]       = handle_get_vcpu_info,
	[KVMI_VCPU_GET_REGISTERS]  = handle_get_registers,
	[KVMI_VCPU_SET_REGISTERS]  = handle_set_registers,
};

static void kvmi_job_vcpu_cmd(struct kvm_vcpu *vcpu, void *ctx)
{
	struct kvmi_vcpu_cmd_job *job = ctx;
	size_t id = job->msg->hdr.id;
	int err;

	job->vcpu = vcpu;

	err = msg_vcpu[id](job, &job->msg->hdr, job->msg + 1);

	if (err) {
		struct kvm_introspection *kvmi = KVMI(vcpu->kvm);

		kvmi_err(kvmi,
			 "%s: cmd id: %zu (%s), err: %d\n", __func__,
			 id, id2str(id), err);
		kvmi_sock_shutdown(kvmi);
	}
}

static void kvmi_free_ctx(void *_ctx)
{
	const struct kvmi_vcpu_cmd_job *ctx = _ctx;

	kvmi_msg_free(ctx->msg);
	kfree(ctx);
}

static int kvmi_msg_queue_to_vcpu(struct kvm_vcpu *vcpu,
				  const struct kvmi_vcpu_cmd_job *cmd)
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

static int kvmi_consume_bytes(struct kvm_introspection *kvmi, size_t bytes)
{
	size_t to_read;
	u8 buf[512];
	int err = 0;

	while (bytes && !err) {
		to_read = min(bytes, sizeof(buf));

		err = kvmi_sock_read(kvmi, buf, to_read);

		bytes -= to_read;
	}

	return err;
}

static struct kvmi_msg_hdr *
kvmi_msg_recv(struct kvm_introspection *kvmi, bool *unsupported)
{
	struct kvmi_msg_hdr *msg;
	int err;

	*unsupported = false;

	msg = kvmi_msg_alloc();
	if (!msg)
		goto out_err;

	err = kvmi_sock_read(kvmi, msg, sizeof(*msg));
	if (err)
		goto out_err;

	if (msg->size > KVMI_MSG_SIZE)
		goto out_err_msg;

	if (is_unsupported_message(msg->id)) {
		if (msg->size && kvmi_consume_bytes(kvmi, msg->size) < 0)
			goto out_err_msg;

		*unsupported = true;
		return msg;
	}

	if (msg->size && kvmi_sock_read(kvmi, msg + 1, msg->size) < 0)
		goto out_err_msg;

	return msg;

out_err_msg:
	kvmi_err(kvmi, "%s id %u (%s) size %u\n",
		 __func__, msg->id, id2str(msg->id), msg->size);

out_err:
	kvmi_msg_free(msg);

	return NULL;
}

static int kvmi_msg_dispatch_vm_cmd(struct kvm_introspection *kvmi,
				    const struct kvmi_msg_hdr *msg)
{
	return msg_vm[msg->id](kvmi, msg, msg + 1);
}

static bool vcpu_can_handle_commands(struct kvm_vcpu *vcpu)
{
	return VCPUI(vcpu)->waiting_for_reply
		|| vcpu->arch.mp_state != KVM_MP_STATE_UNINITIALIZED;
}

static int kvmi_get_vcpu_if_ready(struct kvm_introspection *kvmi,
				  unsigned int vcpu_idx,
				  struct kvm_vcpu **vcpu)
{
	int err;

	err = kvmi_get_vcpu(kvmi, vcpu_idx, vcpu);

	if (!err && !vcpu_can_handle_commands(*vcpu))
		err = -KVM_EAGAIN;

	return err;
}

static int kvmi_msg_dispatch_vcpu_job(struct kvm_introspection *kvmi,
				      struct kvmi_vcpu_cmd_job *job,
				      bool *queued)
{
	struct kvmi_vcpu_hdr *cmd = &job->msg->cmd;
	struct kvmi_msg_hdr *hdr = &job->msg->hdr;
	struct kvm_vcpu *vcpu = NULL;
	int err;

	if (invalid_vcpu_hdr(cmd))
		return -KVM_EINVAL;

	err = kvmi_get_vcpu_if_ready(kvmi, cmd->vcpu, &vcpu);

	if (err)
		return kvmi_msg_vm_reply(kvmi, hdr, err, NULL, 0);

	err = kvmi_msg_queue_to_vcpu(vcpu, job);
	if (!err)
		*queued = true;
	return err;
}

static int kvmi_msg_dispatch_vcpu_cmd(struct kvm_introspection *kvmi,
				      struct kvmi_msg_hdr *msg,
				      bool *queued)
{
	struct kvmi_vcpu_cmd_job *job_cmd;
	int err;

	job_cmd = kzalloc(sizeof(*job_cmd), GFP_KERNEL);
	if (!job_cmd)
		return -KVM_ENOMEM;

	job_cmd->msg = (void *)msg;

	err = kvmi_msg_dispatch_vcpu_job(kvmi, job_cmd, queued);

	if (!*queued)
		kfree(job_cmd);

	return err;
}

static int kvmi_msg_dispatch(struct kvm_introspection *kvmi,
			     struct kvmi_msg_hdr *msg, bool *queued)
{
	int err;

	if (is_vcpu_message(msg->id))
		err = kvmi_msg_dispatch_vcpu_cmd(kvmi, msg, queued);
	else
		err = kvmi_msg_dispatch_vm_cmd(kvmi, msg);

	if (err)
		kvmi_err(kvmi, "%s: msg id: %u (%s), err: %d\n", __func__,
			 msg->id, id2str(msg->id), err);

	return err;
}

static bool is_message_allowed(struct kvm_introspection *kvmi, __u16 id)
{
	if (id == KVMI_EVENT_REPLY)
		return true;

	if (id >= KVMI_NUM_COMMANDS)
		return false;

	return is_command_allowed(kvmi, id);
}

static int kvmi_msg_vm_reply_ec(struct kvm_introspection *kvmi,
				const struct kvmi_msg_hdr *msg, int ec)
{
	return kvmi_msg_vm_reply(kvmi, msg, ec, NULL, 0);
}

bool kvmi_msg_process(struct kvm_introspection *kvmi)
{
	struct kvmi_msg_hdr *msg;
	bool queued = false;
	bool unsupported;
	int err = -1;

	msg = kvmi_msg_recv(kvmi, &unsupported);
	if (!msg)
		goto out;

	if (unsupported) {
		err = kvmi_msg_vm_reply_ec(kvmi, msg, -KVM_ENOSYS);
		goto out;
	}

	if (!is_message_allowed(kvmi, msg->id)) {
		err = kvmi_msg_vm_reply_ec(kvmi, msg, -KVM_EPERM);
		goto out;
	}

	err = kvmi_msg_dispatch(kvmi, msg, &queued);

out:
	if (!queued)
		kvmi_msg_free(msg);

	return err == 0;
}

static inline u32 new_seq(struct kvm_introspection *kvmi)
{
	return atomic_inc_return(&kvmi->ev_seq);
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

int kvmi_msg_send_unhook(struct kvm_introspection *kvmi)
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
	hdr.seq = new_seq(kvmi);
	hdr.size = msg_size - sizeof(hdr);

	kvmi_setup_event_common(&common, KVMI_EVENT_UNHOOK, 0);

	return kvmi_sock_write(kvmi, vec, n, msg_size);
}

static int kvmi_wait_for_reply(struct kvm_vcpu *vcpu)
{
	struct swait_queue_head *wq = kvm_arch_vcpu_wq(vcpu);
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	int err = 0;

	vcpui->waiting_for_reply = true;

	while (vcpui->waiting_for_reply && !err) {
		kvmi_run_jobs(vcpu);

		err = swait_event_killable_exclusive(*wq,
			!vcpui->waiting_for_reply ||
			!list_empty(&vcpui->job_list));
	}

	return err;
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
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	struct kvm_introspection *kvmi = KVMI(vcpu->kvm);
	int err;

	memset(&hdr, 0, sizeof(hdr));
	hdr.id = KVMI_EVENT;
	hdr.seq = new_seq(kvmi);
	hdr.size = msg_size - sizeof(hdr);

	kvmi_setup_event(vcpu, &common, ev_id);

	memset(&vcpui->reply, 0, sizeof(vcpui->reply));

	vcpui->reply.seq = hdr.seq;
	vcpui->reply.data = rpl;
	vcpui->reply.size = rpl_size;
	vcpui->reply.error = -EINTR;

	err = kvmi_sock_write(kvmi, vec, n, msg_size);
	if (err)
		goto out;

	err = kvmi_wait_for_reply(vcpu);
	if (err)
		goto out;

	err = vcpui->reply.error;
	if (err)
		goto out;

	kvmi_post_reply(vcpu);
	*action = vcpui->reply.action;

out:
	if (err)
		kvmi_sock_shutdown(kvmi);
	return err;
}

u32 kvmi_msg_send_vcpu_pause(struct kvm_vcpu *vcpu)
{
	int err, action;

	err = kvmi_send_event(vcpu, KVMI_EVENT_PAUSE_VCPU, NULL, 0,
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
