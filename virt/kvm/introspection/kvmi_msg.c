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
static bool is_vcpu_command(u16 id);

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

int kvmi_msg_vcpu_reply(const struct kvmi_vcpu_msg_job *job,
			const struct kvmi_msg_hdr *msg, int err,
			const void *rpl, size_t rpl_size)
{
	struct kvm_introspection *kvmi = KVMI(job->vcpu->kvm);

	return kvmi_msg_reply(kvmi, msg, err, rpl, rpl_size);
}

static struct kvm_vcpu *kvmi_get_vcpu(struct kvm_introspection *kvmi,
				      unsigned int vcpu_idx)
{
	struct kvm *kvm = kvmi->kvm;

	if (vcpu_idx >= atomic_read(&kvm->online_vcpus))
		return NULL;

	return kvm_get_vcpu(kvm, vcpu_idx);
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
	else if (!is_vm_command(req->id) && !is_vcpu_command(req->id))
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

static int handle_vm_get_info(struct kvm_introspection *kvmi,
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
	int ec;

	if (req->padding1 || req->padding2 || req->enable > 1)
		ec = -KVM_EINVAL;
	else if (!kvmi_is_known_vm_event(req->event_id))
		ec = -KVM_EINVAL;
	else if (!kvmi_is_event_allowed(kvmi, req->event_id))
		ec = -KVM_EPERM;
	else
		ec = kvmi_cmd_vm_control_events(kvmi, req->event_id,
						req->enable == 1);

	return kvmi_msg_vm_reply(kvmi, msg, ec, NULL, 0);
}

static bool invalid_page_access(u64 gpa, u64 size)
{
	u64 off = gpa & ~PAGE_MASK;

	return (size == 0 || size > PAGE_SIZE || off + size > PAGE_SIZE);
}

static int handle_vm_read_physical(struct kvm_introspection *kvmi,
				   const struct kvmi_msg_hdr *msg,
				   const void *_req)
{
	const struct kvmi_vm_read_physical *req = _req;

	if (invalid_page_access(req->gpa, req->size) ||
	    req->padding1 || req->padding2)
		return kvmi_msg_vm_reply(kvmi, msg, -KVM_EINVAL, NULL, 0);

	return kvmi_cmd_read_physical(kvmi->kvm, req->gpa, req->size,
				      kvmi_msg_vm_reply, msg);
}

static int handle_vm_write_physical(struct kvm_introspection *kvmi,
				    const struct kvmi_msg_hdr *msg,
				    const void *_req)
{
	const struct kvmi_vm_write_physical *req = _req;
	int ec;

	if (struct_size(req, data, req->size) > msg->size)
		return -EINVAL;

	if (invalid_page_access(req->gpa, req->size))
		ec = -KVM_EINVAL;
	else if (req->padding1 || req->padding2)
		ec = -KVM_EINVAL;
	else
		ec = kvmi_cmd_write_physical(kvmi->kvm, req->gpa,
					     req->size, req->data);

	return kvmi_msg_vm_reply(kvmi, msg, ec, NULL, 0);
}

static int handle_vm_pause_vcpu(struct kvm_introspection *kvmi,
				const struct kvmi_msg_hdr *msg,
				const void *_req)
{
	const struct kvmi_vm_pause_vcpu *req = _req;
	struct kvm_vcpu *vcpu;
	int ec;

	if (req->wait > 1 || req->padding1 || req->padding2) {
		ec = -KVM_EINVAL;
		goto reply;
	}

	if (!kvmi_is_event_allowed(kvmi, KVMI_VCPU_EVENT_PAUSE)) {
		ec = -KVM_EPERM;
		goto reply;
	}

	vcpu = kvmi_get_vcpu(kvmi, req->vcpu);
	if (!vcpu)
		ec = -KVM_EINVAL;
	else
		ec = kvmi_cmd_vcpu_pause(vcpu, req->wait == 1);

reply:
	return kvmi_msg_vm_reply(kvmi, msg, ec, NULL, 0);
}

/*
 * These commands are executed by the receiving thread.
 */
static kvmi_vm_msg_fct const msg_vm[] = {
	[KVMI_GET_VERSION]       = handle_get_version,
	[KVMI_VM_CHECK_COMMAND]  = handle_vm_check_command,
	[KVMI_VM_CHECK_EVENT]    = handle_vm_check_event,
	[KVMI_VM_CONTROL_EVENTS] = handle_vm_control_events,
	[KVMI_VM_GET_INFO]       = handle_vm_get_info,
	[KVMI_VM_PAUSE_VCPU]     = handle_vm_pause_vcpu,
	[KVMI_VM_READ_PHYSICAL]  = handle_vm_read_physical,
	[KVMI_VM_WRITE_PHYSICAL] = handle_vm_write_physical,
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
	return is_vm_message(id) && id != KVMI_VM_EVENT;
}

static int check_event_reply(const struct kvmi_msg_hdr *msg,
			     const struct kvmi_vcpu_event_reply *reply,
			     const struct kvmi_vcpu_reply *expected,
			     u8 *action, size_t *received)
{
	size_t msg_size, common_size, event_size;
	int err = -EINVAL;

	if (unlikely(msg->seq != expected->seq))
		return err;

	msg_size = msg->size;
	common_size = sizeof(struct kvmi_vcpu_hdr) + sizeof(*reply);

	if (check_sub_overflow(msg_size, common_size, &event_size))
		return err;

	if (unlikely(event_size > expected->size))
		return err;

	if (unlikely(reply->padding1 || reply->padding2))
		return err;

	*received = event_size;
	*action = reply->action;
	return 0;
}

static int handle_vcpu_event_reply(const struct kvmi_vcpu_msg_job *job,
				   const struct kvmi_msg_hdr *msg,
				   const void *rpl)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(job->vcpu);
	struct kvmi_vcpu_reply *expected = &vcpui->reply;
	const struct kvmi_vcpu_event_reply *reply = rpl;
	const void *reply_data = reply + 1;
	size_t useful, received;
	int err = -EINTR;
	u8 action;

	if (unlikely(!vcpui->waiting_for_reply))
		goto out;

	err = check_event_reply(msg, reply, expected, &action, &received);
	if (unlikely(err))
		goto out;

	useful = min(received, expected->size);
	if (useful)
		memcpy(expected->data, reply_data, useful);

	if (expected->size > useful)
		memset((char *)expected->data + useful, 0,
			expected->size - useful);

	expected->action = action;

out:
	vcpui->waiting_for_reply = false;
	expected->error = err;
	return expected->error;
}

static int handle_vcpu_control_events(const struct kvmi_vcpu_msg_job *job,
				      const struct kvmi_msg_hdr *msg,
				      const void *_req)
{
	struct kvm_introspection *kvmi = KVMI(job->vcpu->kvm);
	const struct kvmi_vcpu_control_events *req = _req;
	int ec;

	if (req->padding1 || req->padding2 || req->enable > 1)
		ec = -KVM_EINVAL;
	else if (!kvmi_is_known_vcpu_event(req->event_id))
		ec = -KVM_EINVAL;
	else if (!kvmi_is_event_allowed(kvmi, req->event_id))
		ec = -KVM_EPERM;
	else
		ec = kvmi_cmd_vcpu_control_events(job->vcpu, req->event_id,
						  req->enable == 1);

	return kvmi_msg_vcpu_reply(job, msg, ec, NULL, 0);
}

/*
 * These functions are executed from the vCPU thread. The receiving thread
 * passes the messages using a newly allocated 'struct kvmi_vcpu_msg_job'
 * and signals the vCPU to handle the message (which includes
 * sending back the reply).
 */
static kvmi_vcpu_msg_job_fct const msg_vcpu[] = {
	[KVMI_VCPU_EVENT]          = handle_vcpu_event_reply,
	[KVMI_VCPU_CONTROL_EVENTS] = handle_vcpu_control_events,
};

static kvmi_vcpu_msg_job_fct get_vcpu_msg_handler(u16 id)
{
	kvmi_vcpu_msg_job_fct fct;

	fct = id < ARRAY_SIZE(msg_vcpu) ? msg_vcpu[id] : NULL;

	if (!fct)
		fct = kvmi_arch_vcpu_msg_handler(id);

	return fct;
}

static bool is_vcpu_message(u16 id)
{
	bool is_vcpu_msg_id = id & 1;

	return is_vcpu_msg_id && !!get_vcpu_msg_handler(id);
}

static bool is_vcpu_command(u16 id)
{
	return is_vcpu_message(id) && id != KVMI_VCPU_EVENT;
}

static void kvmi_job_vcpu_msg(struct kvm_vcpu *vcpu, void *ctx)
{
	struct kvmi_vcpu_msg_job *job = ctx;
	kvmi_vcpu_msg_job_fct fct;
	int err;

	job->vcpu = vcpu;

	fct = get_vcpu_msg_handler(job->msg->hdr.id);
	err = fct(job, &job->msg->hdr, job->msg + 1);

	/*
	 * The soft errors are sent with the reply.
	 * On hard errors, like this one,
	 * we shut down the socket.
	 */
	if (err)
		kvmi_sock_shutdown(KVMI(vcpu->kvm));
}

static void kvmi_free_ctx(void *_ctx)
{
	const struct kvmi_vcpu_msg_job *ctx = _ctx;

	kvmi_msg_free(ctx->msg);
	kfree(ctx);
}

static int kvmi_msg_queue_to_vcpu(struct kvm_vcpu *vcpu,
				  const struct kvmi_vcpu_msg_job *cmd)
{
	return kvmi_add_job(vcpu, kvmi_job_vcpu_msg, (void *)cmd,
			    kvmi_free_ctx);
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

static bool vcpu_can_handle_messages(struct kvm_vcpu *vcpu)
{
	return VCPUI(vcpu)->waiting_for_reply
		|| vcpu->arch.mp_state != KVM_MP_STATE_UNINITIALIZED;
}

static int kvmi_get_vcpu_if_ready(struct kvm_introspection *kvmi,
				  unsigned int vcpu_idx,
				  struct kvm_vcpu **vcpu)
{
	*vcpu = kvmi_get_vcpu(kvmi, vcpu_idx);
	if (*vcpu == NULL)
		return -KVM_EINVAL;

	if (!vcpu_can_handle_messages(*vcpu))
		return -KVM_EAGAIN;

	return 0;
}

static int kvmi_msg_dispatch_vcpu_msg(struct kvm_introspection *kvmi,
				      struct kvmi_msg_hdr *msg,
				      struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu_msg_job *job_cmd;
	int err;

	job_cmd = kzalloc(sizeof(*job_cmd), GFP_KERNEL);
	if (!job_cmd)
		return -ENOMEM;

	job_cmd->msg = (void *)msg;

	err = kvmi_msg_queue_to_vcpu(vcpu, job_cmd);
	if (err)
		kfree(job_cmd);

	return err;
}

static int kvmi_msg_handle_vcpu_msg(struct kvm_introspection *kvmi,
				    struct kvmi_msg_hdr *msg,
				    bool *queued)
{
	struct kvmi_vcpu_hdr *vcpu_hdr = (struct kvmi_vcpu_hdr *)(msg + 1);
	struct kvm_vcpu *vcpu = NULL;
	int err, ec;

	if (msg->id != KVMI_VCPU_EVENT &&
	    !kvmi_is_command_allowed(kvmi, msg->id))
		return kvmi_msg_vm_reply_ec(kvmi, msg, -KVM_EPERM);

	if (vcpu_hdr->padding1 || vcpu_hdr->padding2)
		return kvmi_msg_vm_reply_ec(kvmi, msg, -KVM_EINVAL);

	ec = kvmi_get_vcpu_if_ready(kvmi, vcpu_hdr->vcpu, &vcpu);
	if (ec)
		return kvmi_msg_vm_reply_ec(kvmi, msg, ec);

	err = kvmi_msg_dispatch_vcpu_msg(kvmi, msg, vcpu);
	*queued = err == 0;
	return err;
}

bool kvmi_msg_process(struct kvm_introspection *kvmi)
{
	struct kvmi_msg_hdr *msg;
	bool queued = false;
	int err = -1;

	msg = kvmi_msg_recv(kvmi);
	if (!msg)
		goto out;

	if (is_vm_command(msg->id))
		err = kvmi_msg_handle_vm_cmd(kvmi, msg);
	else if (is_vcpu_message(msg->id))
		err = kvmi_msg_handle_vcpu_msg(kvmi, msg, &queued);
	else
		err = kvmi_msg_vm_reply_ec(kvmi, msg, -KVM_ENOSYS);

	if (!queued)
		kvmi_msg_free(msg);
out:
	return err == 0;
}

static void kvmi_fill_ev_msg_hdr(struct kvm_introspection *kvmi,
				 struct kvmi_msg_hdr *msg_hdr,
				 struct kvmi_event_hdr *ev_hdr,
				 u16 msg_id, u32 msg_seq,
				 size_t msg_size, u16 ev_id)
{
	memset(msg_hdr, 0, sizeof(*msg_hdr));
	msg_hdr->id = msg_id;
	msg_hdr->seq = msg_seq;
	msg_hdr->size = msg_size - sizeof(*msg_hdr);

	memset(ev_hdr, 0, sizeof(*ev_hdr));
	ev_hdr->event = ev_id;
}

static void kvmi_fill_vm_event(struct kvm_introspection *kvmi,
			       struct kvmi_msg_hdr *msg_hdr,
			       struct kvmi_event_hdr *ev_hdr,
			       u16 ev_id, size_t msg_size)
{
	u32 msg_seq = atomic_inc_return(&kvmi->ev_seq);

	kvmi_fill_ev_msg_hdr(kvmi, msg_hdr, ev_hdr, KVMI_VM_EVENT,
			     msg_seq, msg_size, ev_id);
}

int kvmi_msg_send_unhook(struct kvm_introspection *kvmi)
{
	struct kvmi_msg_hdr msg_hdr;
	struct kvmi_event_hdr ev_hdr;
	struct kvec vec[] = {
		{.iov_base = &msg_hdr, .iov_len = sizeof(msg_hdr)},
		{.iov_base = &ev_hdr,  .iov_len = sizeof(ev_hdr) },
	};
	size_t msg_size = sizeof(msg_hdr) + sizeof(ev_hdr);
	size_t n = ARRAY_SIZE(vec);

	kvmi_fill_vm_event(kvmi, &msg_hdr, &ev_hdr,
			   KVMI_VM_EVENT_UNHOOK, msg_size);

	return kvmi_sock_write(kvmi, vec, n, msg_size);
}

static int kvmi_wait_for_reply(struct kvm_vcpu *vcpu)
{
	struct rcuwait *waitp = kvm_arch_vcpu_get_wait(vcpu);
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	int err = 0;

	while (vcpui->waiting_for_reply && !err) {
		kvmi_run_jobs(vcpu);

		err = rcuwait_wait_event(waitp,
			!vcpui->waiting_for_reply ||
			!list_empty(&vcpui->job_list),
			TASK_KILLABLE);
	}

	return err;
}

static void kvmi_setup_vcpu_reply(struct kvm_vcpu_introspection *vcpui,
				  u32 msg_seq, void *rpl, size_t rpl_size)
{
	memset(&vcpui->reply, 0, sizeof(vcpui->reply));

	vcpui->reply.seq = msg_seq;
	vcpui->reply.data = rpl;
	vcpui->reply.size = rpl_size;
	vcpui->reply.error = -EINTR;
	vcpui->waiting_for_reply = true;
}

static int kvmi_fill_and_sent_vcpu_event(struct kvm_vcpu *vcpu,
					 u32 ev_id, void *ev,
					 size_t ev_size, u32 msg_seq)
{
	struct kvmi_msg_hdr msg_hdr;
	struct kvmi_event_hdr ev_hdr;
	struct kvmi_vcpu_event common;
	struct kvec vec[] = {
		{.iov_base = &msg_hdr, .iov_len = sizeof(msg_hdr)},
		{.iov_base = &ev_hdr,  .iov_len = sizeof(ev_hdr) },
		{.iov_base = &common,  .iov_len = sizeof(common) },
		{.iov_base = ev,       .iov_len = ev_size        },
	};
	size_t msg_size = sizeof(msg_hdr) + sizeof(ev_hdr)
			+ sizeof(common) + ev_size;
	size_t n = ARRAY_SIZE(vec) - (ev_size == 0 ? 1 : 0);
	struct kvm_introspection *kvmi = KVMI(vcpu->kvm);

	kvmi_fill_ev_msg_hdr(kvmi, &msg_hdr, &ev_hdr, KVMI_VCPU_EVENT,
			     msg_seq, msg_size, ev_id);

	common.size = sizeof(common);
	common.vcpu = kvm_vcpu_get_idx(vcpu);

	kvmi_arch_setup_vcpu_event(vcpu, &common);

	return kvmi_sock_write(kvmi, vec, n, msg_size);
}

int kvmi_send_vcpu_event(struct kvm_vcpu *vcpu, u32 ev_id,
			 void *ev, size_t ev_size,
			 void *rpl, size_t rpl_size, u32 *action)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	struct kvm_introspection *kvmi = KVMI(vcpu->kvm);
	u32 msg_seq = atomic_inc_return(&kvmi->ev_seq);
	int err;

	kvmi_setup_vcpu_reply(vcpui, msg_seq, rpl, rpl_size);

	err = kvmi_fill_and_sent_vcpu_event(vcpu, ev_id, ev, ev_size, msg_seq);
	if (err)
		goto out;

	err = kvmi_wait_for_reply(vcpu);
	if (!err)
		err = vcpui->reply.error;

out:
	vcpui->waiting_for_reply = false;

	if (err) {
		kvmi_sock_shutdown(kvmi);
	} else {
		kvmi_arch_post_reply(vcpu);
		*action = vcpui->reply.action;
	}

	return err;
}

u32 kvmi_msg_send_vcpu_pause(struct kvm_vcpu *vcpu)
{
	u32 action;
	int err;

	err = kvmi_send_vcpu_event(vcpu, KVMI_VCPU_EVENT_PAUSE, NULL, 0,
				   NULL, 0, &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	return action;
}

u32 kvmi_msg_send_vcpu_hypercall(struct kvm_vcpu *vcpu)
{
	u32 action;
	int err;

	err = kvmi_send_vcpu_event(vcpu, KVMI_VCPU_EVENT_HYPERCALL, NULL, 0,
				   NULL, 0, &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	return action;
}

u32 kvmi_msg_send_vcpu_bp(struct kvm_vcpu *vcpu, u64 gpa, u8 insn_len)
{
	struct kvmi_vcpu_event_breakpoint e;
	u32 action;
	int err;

	memset(&e, 0, sizeof(e));
	e.gpa = gpa;
	e.insn_len = insn_len;

	err = kvmi_send_vcpu_event(vcpu, KVMI_VCPU_EVENT_BREAKPOINT,
				   &e, sizeof(e), NULL, 0, &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	return action;
}
