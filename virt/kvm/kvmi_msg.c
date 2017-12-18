// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection
 *
 * Copyright (C) 2017 Bitdefender S.R.L.
 *
 */
#include <linux/file.h>
#include <linux/net.h>
#include <linux/kvm_host.h>
#include <linux/kvmi.h>
#include <asm/virtext.h>

#include <uapi/linux/kvmi.h>
#include <uapi/asm/kvmi.h>

#include "kvmi_int.h"

/* TODO: split this into arch-independent and x86 */

#include <trace/events/kvmi.h>

/*
 * TODO: break these call paths
 *   kvmi.c        work_cb
 *   kvmi_msg.c    kvmi_dispatch_message
 *   kvmi.c        kvmi_cmd_... / kvmi_make_request
 *   kvmi_msg.c    kvmi_msg_reply
 *
 *   kvmi.c        kvmi_X_event
 *   kvmi_msg.c    kvmi_send_event
 *   kvmi.c        kvmi_handle_request
 */

/* TODO: move some of the code to arch/x86 */

static atomic_t seq_ev = ATOMIC_INIT(0);

static u32 new_seq(void)
{
	return atomic_inc_return(&seq_ev);
}

static const char * const msg_IDs[] = {
	[KVMI_GET_VERSION]      = "KVMI_GET_VERSION",
	[KVMI_GET_GUEST_INFO]   = "KVMI_GET_GUEST_INFO",
	[KVMI_PAUSE_VCPU]       = "KVMI_PAUSE_VCPU",
	[KVMI_GET_REGISTERS]    = "KVMI_GET_REGISTERS",
	[KVMI_SET_REGISTERS]    = "KVMI_SET_REGISTERS",
	[KVMI_GET_PAGE_ACCESS]  = "KVMI_GET_PAGE_ACCESS",
	[KVMI_SET_PAGE_ACCESS]  = "KVMI_SET_PAGE_ACCESS",
	[KVMI_INJECT_EXCEPTION] = "KVMI_INJECT_EXCEPTION",
	[KVMI_READ_PHYSICAL]    = "KVMI_READ_PHYSICAL",
	[KVMI_WRITE_PHYSICAL]   = "KVMI_WRITE_PHYSICAL",
	[KVMI_GET_MAP_TOKEN]    = "KVMI_GET_MAP_TOKEN",
	[KVMI_CONTROL_EVENTS]   = "KVMI_CONTROL_EVENTS",
	[KVMI_CONTROL_CR]       = "KVMI_CONTROL_CR",
	[KVMI_CONTROL_MSR]      = "KVMI_CONTROL_MSR",
	[KVMI_EVENT]            = "KVMI_EVENT",
	[KVMI_EVENT_REPLY]      = "KVMI_EVENT_REPLY",
	[KVMI_GET_CPUID]        = "KVMI_GET_CPUID",
	[KVMI_GET_XSAVE]        = "KVMI_GET_XSAVE",
};

static size_t sizeof_get_registers(const void *r)
{
	const struct kvmi_get_registers *req = r;

	return sizeof(*req) + sizeof(req->msrs_idx[0]) * req->nmsrs;
}

static size_t sizeof_get_page_access(const void *r)
{
	const struct kvmi_get_page_access *req = r;

	return sizeof(*req) + sizeof(req->gpa[0]) * req->count;
}

static size_t sizeof_set_page_access(const void *r)
{
	const struct kvmi_set_page_access *req = r;

	return sizeof(*req) + sizeof(req->entries[0]) * req->count;
}

static size_t sizeof_write_physical(const void *r)
{
	const struct kvmi_write_physical *req = r;

	return sizeof(*req) + req->size;
}

static const struct {
	size_t size;
	size_t (*cbk_full_size)(const void *msg);
} msg_bytes[] = {
	[KVMI_GET_VERSION]      = { 0, NULL },
	[KVMI_GET_GUEST_INFO]   = { sizeof(struct kvmi_get_guest_info), NULL },
	[KVMI_PAUSE_VCPU]       = { sizeof(struct kvmi_pause_vcpu), NULL },
	[KVMI_GET_REGISTERS]    = { sizeof(struct kvmi_get_registers),
						sizeof_get_registers },
	[KVMI_SET_REGISTERS]    = { sizeof(struct kvmi_set_registers), NULL },
	[KVMI_GET_PAGE_ACCESS]  = { sizeof(struct kvmi_get_page_access),
						sizeof_get_page_access },
	[KVMI_SET_PAGE_ACCESS]  = { sizeof(struct kvmi_set_page_access),
						sizeof_set_page_access },
	[KVMI_INJECT_EXCEPTION] = { sizeof(struct kvmi_inject_exception),
					NULL },
	[KVMI_READ_PHYSICAL]    = { sizeof(struct kvmi_read_physical), NULL },
	[KVMI_WRITE_PHYSICAL]   = { sizeof(struct kvmi_write_physical),
						sizeof_write_physical },
	[KVMI_GET_MAP_TOKEN]    = { 0, NULL },
	[KVMI_CONTROL_EVENTS]   = { sizeof(struct kvmi_control_events), NULL },
	[KVMI_CONTROL_CR]       = { sizeof(struct kvmi_control_cr), NULL },
	[KVMI_CONTROL_MSR]      = { sizeof(struct kvmi_control_msr), NULL },
	[KVMI_GET_CPUID]        = { sizeof(struct kvmi_get_cpuid), NULL },
	[KVMI_GET_XSAVE]        = { sizeof(struct kvmi_get_xsave), NULL },
};

static int kvmi_sock_read(struct kvmi *ikvm, void *buf, size_t size)
{
	struct kvec i = {
		.iov_base = buf,
		.iov_len = size,
	};
	struct msghdr m = { };
	int rc;

	read_lock(&ikvm->sock_lock);

	if (likely(ikvm->sock))
		rc = kernel_recvmsg(ikvm->sock, &m, &i, 1, size, MSG_WAITALL);
	else
		rc = -EPIPE;

	if (rc > 0)
		print_hex_dump_debug("read: ", DUMP_PREFIX_NONE, 32, 1,
					buf, rc, false);

	read_unlock(&ikvm->sock_lock);

	if (unlikely(rc != size)) {
		kvm_err("kernel_recvmsg: %d\n", rc);
		if (rc >= 0)
			rc = -EPIPE;
		return rc;
	}

	return 0;
}

static int kvmi_sock_write(struct kvmi *ikvm, struct kvec *i, size_t n,
			   size_t size)
{
	struct msghdr m = { };
	int rc, k;

	read_lock(&ikvm->sock_lock);

	if (likely(ikvm->sock))
		rc = kernel_sendmsg(ikvm->sock, &m, i, n, size);
	else
		rc = -EPIPE;

	for (k = 0; k < n; k++)
		print_hex_dump_debug("write: ", DUMP_PREFIX_NONE, 32, 1,
				     i[k].iov_base, i[k].iov_len, false);

	read_unlock(&ikvm->sock_lock);

	if (unlikely(rc != size)) {
		kvm_err("kernel_sendmsg: %d\n", rc);
		if (rc >= 0)
			rc = -EPIPE;
		return rc;
	}

	return 0;
}

static const char *id2str(int i)
{
	return (i < ARRAY_SIZE(msg_IDs) && msg_IDs[i] ? msg_IDs[i] : "unknown");
}

static struct kvmi_vcpu *kvmi_vcpu_waiting_for_reply(struct kvm *kvm, u32 seq)
{
	struct kvmi_vcpu *found = NULL;
	struct kvm_vcpu *vcpu;
	int i;

	mutex_lock(&kvm->lock);

	kvm_for_each_vcpu(i, vcpu, kvm) {
		/* kvmi_send_event */
		smp_rmb();
		if (READ_ONCE(IVCPU(vcpu)->ev_rpl_waiting)
		    && seq == IVCPU(vcpu)->ev_seq) {
			found = IVCPU(vcpu);
			break;
		}
	}

	mutex_unlock(&kvm->lock);

	return found;
}

static bool kvmi_msg_dispatch_reply(struct kvmi *ikvm,
				    const struct kvmi_msg_hdr *msg)
{
	struct kvmi_vcpu *ivcpu;
	int err;

	ivcpu = kvmi_vcpu_waiting_for_reply(ikvm->kvm, msg->seq);
	if (!ivcpu) {
		kvm_err("%s: unexpected event reply (seq=%u)\n", __func__,
			msg->seq);
		return false;
	}

	if (msg->size == sizeof(ivcpu->ev_rpl) + ivcpu->ev_rpl_size) {
		err = kvmi_sock_read(ikvm, &ivcpu->ev_rpl,
					sizeof(ivcpu->ev_rpl));
		if (!err && ivcpu->ev_rpl_size)
			err = kvmi_sock_read(ikvm, ivcpu->ev_rpl_ptr,
						ivcpu->ev_rpl_size);
	} else {
		kvm_err("%s: invalid event reply size (max=%zu, recv=%u, expected=%zu)\n",
			__func__, ivcpu->ev_rpl_size, msg->size,
			sizeof(ivcpu->ev_rpl) + ivcpu->ev_rpl_size);
		err = -1;
	}

	ivcpu->ev_rpl_received = err ? -1 : ivcpu->ev_rpl_size;

	kvmi_make_request(ivcpu, REQ_REPLY);

	return (err == 0);
}

static bool consume_sock_bytes(struct kvmi *ikvm, size_t n)
{
	while (n) {
		u8 buf[256];
		size_t chunk = min(n, sizeof(buf));

		if (kvmi_sock_read(ikvm, buf, chunk) != 0)
			return false;

		n -= chunk;
	}

	return true;
}

static int kvmi_msg_reply(struct kvmi *ikvm,
			  const struct kvmi_msg_hdr *msg,
			  int err, const void *rpl, size_t rpl_size)
{
	struct kvmi_error_code ec;
	struct kvmi_msg_hdr h;
	struct kvec vec[3] = {
		{.iov_base = &h,           .iov_len = sizeof(h) },
		{.iov_base = &ec,          .iov_len = sizeof(ec)},
		{.iov_base = (void *) rpl, .iov_len = rpl_size  },
	};
	size_t size = sizeof(h) + sizeof(ec) + (err ? 0 : rpl_size);
	size_t n = err ? ARRAY_SIZE(vec)-1 : ARRAY_SIZE(vec);

	memset(&h, 0, sizeof(h));
	h.id = msg->id;
	h.seq = msg->seq;
	h.size = size - sizeof(h);

	memset(&ec, 0, sizeof(ec));
	ec.err = err;

	return kvmi_sock_write(ikvm, vec, n, size);
}

static int kvmi_msg_vcpu_reply(struct kvm_vcpu *vcpu,
				const struct kvmi_msg_hdr *msg,
				int err, const void *rpl, size_t size)
{
	/*
	 * As soon as we reply to this vCPU command, we can get another one,
	 * and we must signal that the incoming buffer (ivcpu->msg_buf)
	 * is ready by clearing this bit/request.
	 */
	kvmi_clear_request(IVCPU(vcpu), REQ_CMD);

	return kvmi_msg_reply(IKVM(vcpu->kvm), msg, err, rpl, size);
}

bool kvmi_msg_init(struct kvmi *ikvm, int fd)
{
	struct socket *sock;
	int r;

	sock = sockfd_lookup(fd, &r);

	if (!sock) {
		kvm_err("Invalid file handle: %d\n", fd);
		return false;
	}

	WRITE_ONCE(ikvm->sock, sock);

	return true;
}

void kvmi_msg_uninit(struct kvmi *ikvm)
{
	kvm_info("Wake up the receiving thread\n");

	read_lock(&ikvm->sock_lock);

	if (ikvm->sock)
		kernel_sock_shutdown(ikvm->sock, SHUT_RDWR);

	read_unlock(&ikvm->sock_lock);

	kvm_info("Wait for the receiving thread to complete\n");
	wait_for_completion(&ikvm->finished);
}

static int handle_get_version(struct kvmi *ikvm,
			      const struct kvmi_msg_hdr *msg, const void *req)
{
	struct kvmi_get_version_reply rpl;

	memset(&rpl, 0, sizeof(rpl));
	rpl.version = KVMI_VERSION;

	return kvmi_msg_reply(ikvm, msg, 0, &rpl, sizeof(rpl));
}

static struct kvm_vcpu *kvmi_get_vcpu(struct kvmi *ikvm, int vcpu_id)
{
	struct kvm *kvm = ikvm->kvm;

	if (vcpu_id >= atomic_read(&kvm->online_vcpus))
		return NULL;

	return kvm_get_vcpu(kvm, vcpu_id);
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

	if (invalid_page_access(req->gpa, req->size))
		return -EINVAL;

	return kvmi_cmd_read_physical(ikvm->kvm, req->gpa, req->size,
				      kvmi_msg_reply, msg);
}

static int handle_write_physical(struct kvmi *ikvm,
				 const struct kvmi_msg_hdr *msg,
				 const void *_req)
{
	const struct kvmi_write_physical *req = _req;
	int ec;

	if (invalid_page_access(req->gpa, req->size))
		return -EINVAL;

	ec = kvmi_cmd_write_physical(ikvm->kvm, req->gpa, req->size, req->data);

	return kvmi_msg_reply(ikvm, msg, ec, NULL, 0);
}

static int handle_get_map_token(struct kvmi *ikvm,
				const struct kvmi_msg_hdr *msg,
				const void *_req)
{
	struct kvmi_get_map_token_reply rpl;
	int ec;

	ec = kvmi_cmd_alloc_token(ikvm->kvm, &rpl.token);

	return kvmi_msg_reply(ikvm, msg, ec, &rpl, sizeof(rpl));
}

static int handle_control_cr(struct kvmi *ikvm,
			     const struct kvmi_msg_hdr *msg, const void *_req)
{
	const struct kvmi_control_cr *req = _req;
	int ec;

	ec = kvmi_cmd_control_cr(ikvm, req->enable, req->cr);

	return kvmi_msg_reply(ikvm, msg, ec, NULL, 0);
}

static int handle_control_msr(struct kvmi *ikvm,
			      const struct kvmi_msg_hdr *msg, const void *_req)
{
	const struct kvmi_control_msr *req = _req;
	int ec;

	ec = kvmi_cmd_control_msr(ikvm->kvm, req->enable, req->msr);

	return kvmi_msg_reply(ikvm, msg, ec, NULL, 0);
}

/*
 * These commands are executed on the receiving thread/worker.
 */
static int (*const msg_vm[])(struct kvmi *, const struct kvmi_msg_hdr *,
			     const void *) = {
	[KVMI_GET_VERSION]    = handle_get_version,
	[KVMI_READ_PHYSICAL]  = handle_read_physical,
	[KVMI_WRITE_PHYSICAL] = handle_write_physical,
	[KVMI_GET_MAP_TOKEN]  = handle_get_map_token,
	[KVMI_CONTROL_CR]     = handle_control_cr,
	[KVMI_CONTROL_MSR]    = handle_control_msr,
};

static int handle_get_guest_info(struct kvm_vcpu *vcpu,
				 const struct kvmi_msg_hdr *msg,
				 const void *req)
{
	struct kvmi_get_guest_info_reply rpl;

	memset(&rpl, 0, sizeof(rpl));
	kvmi_cmd_get_guest_info(vcpu, &rpl.vcpu_count, &rpl.tsc_speed);

	return kvmi_msg_vcpu_reply(vcpu, msg, 0, &rpl, sizeof(rpl));
}

static int handle_pause_vcpu(struct kvm_vcpu *vcpu,
			     const struct kvmi_msg_hdr *msg,
			     const void *req)
{
	int ec = kvmi_cmd_pause_vcpu(vcpu);

	return kvmi_msg_vcpu_reply(vcpu, msg, ec, NULL, 0);
}

static void *alloc_get_registers_reply(const struct kvmi_msg_hdr *msg,
				       const struct kvmi_get_registers *req,
				       size_t *rpl_size)
{
	struct kvmi_get_registers_reply *rpl;
	u16 k, n = req->nmsrs;

	*rpl_size = sizeof(*rpl) + sizeof(rpl->msrs.entries[0]) * n;

	rpl = kzalloc(*rpl_size, GFP_KERNEL);

	if (rpl) {
		rpl->msrs.nmsrs = n;

		for (k = 0; k < n; k++)
			rpl->msrs.entries[k].index = req->msrs_idx[k];
	}

	return rpl;
}

static int handle_get_registers(struct kvm_vcpu *vcpu,
				const struct kvmi_msg_hdr *msg, const void *req)
{
	struct kvmi_get_registers_reply *rpl;
	size_t rpl_size = 0;
	int err, ec;

	rpl = alloc_get_registers_reply(msg, req, &rpl_size);

	if (!rpl)
		ec = -KVM_ENOMEM;
	else
		ec = kvmi_cmd_get_registers(vcpu, &rpl->mode,
						&rpl->regs, &rpl->sregs,
						&rpl->msrs);

	err = kvmi_msg_vcpu_reply(vcpu, msg, ec, rpl, rpl_size);
	kfree(rpl);
	return err;
}

static int handle_set_registers(struct kvm_vcpu *vcpu,
				const struct kvmi_msg_hdr *msg,
				const void *_req)
{
	const struct kvmi_set_registers *req = _req;
	int ec;

	ec = kvmi_cmd_set_registers(vcpu, &req->regs);

	return kvmi_msg_vcpu_reply(vcpu, msg, ec, NULL, 0);
}

static int handle_get_page_access(struct kvm_vcpu *vcpu,
				  const struct kvmi_msg_hdr *msg,
				  const void *_req)
{
	const struct kvmi_get_page_access *req = _req;
	struct kvmi_get_page_access_reply *rpl = NULL;
	size_t rpl_size = 0;
	u16 k, n = req->count;
	int err, ec = 0;

	if (req->view != 0 && !kvm_eptp_switching_supported) {
		ec = -KVM_ENOSYS;
		goto out;
	}

	if (req->view != 0) { /* TODO */
		ec = -KVM_EINVAL;
		goto out;
	}

	rpl_size = sizeof(*rpl) + sizeof(rpl->access[0]) * n;
	rpl = kzalloc(rpl_size, GFP_KERNEL);

	if (!rpl) {
		ec = -KVM_ENOMEM;
		goto out;
	}

	for (k = 0; k < n && ec == 0; k++)
		ec = kvmi_cmd_get_page_access(vcpu, req->gpa[k],
						&rpl->access[k]);

out:
	err = kvmi_msg_vcpu_reply(vcpu, msg, ec, rpl, rpl_size);
	kfree(rpl);
	return err;
}

static int handle_set_page_access(struct kvm_vcpu *vcpu,
				  const struct kvmi_msg_hdr *msg,
				  const void *_req)
{
	const struct kvmi_set_page_access *req = _req;
	struct kvm *kvm = vcpu->kvm;
	u16 k, n = req->count;
	int ec = 0;

	if (req->view != 0) {
		if (!kvm_eptp_switching_supported)
			ec = -KVM_ENOSYS;
		else
			ec = -KVM_EINVAL; /* TODO */
	} else {
		for (k = 0; k < n; k++) {
			u64 gpa   = req->entries[k].gpa;
			u8 access = req->entries[k].access;
			int ec0;

			if (access &  ~(KVMI_PAGE_ACCESS_R |
					KVMI_PAGE_ACCESS_W |
					KVMI_PAGE_ACCESS_X))
				ec0 = -KVM_EINVAL;
			else
				ec0 = kvmi_set_mem_access(kvm, gpa, access);

			if (ec0 && !ec)
				ec = ec0;

			trace_kvmi_set_mem_access(gpa_to_gfn(gpa), access, ec0);
		}
	}

	return kvmi_msg_vcpu_reply(vcpu, msg, ec, NULL, 0);
}

static int handle_inject_exception(struct kvm_vcpu *vcpu,
				   const struct kvmi_msg_hdr *msg,
				   const void *_req)
{
	const struct kvmi_inject_exception *req = _req;
	int ec;

	ec = kvmi_cmd_inject_exception(vcpu, req->nr, req->has_error,
				       req->error_code, req->address);

	return kvmi_msg_vcpu_reply(vcpu, msg, ec, NULL, 0);
}

static int handle_control_events(struct kvm_vcpu *vcpu,
				 const struct kvmi_msg_hdr *msg,
				 const void *_req)
{
	const struct kvmi_control_events *req = _req;
	u32 not_allowed = ~IKVM(vcpu->kvm)->event_allow_mask;
	u32 unknown = ~KVMI_KNOWN_EVENTS;
	int ec;

	if (req->events & unknown)
		ec = -KVM_EINVAL;
	else if (req->events & not_allowed)
		ec = -KVM_EPERM;
	else
		ec = kvmi_cmd_control_events(vcpu, req->events);

	return kvmi_msg_vcpu_reply(vcpu, msg, ec, NULL, 0);
}

static int handle_get_cpuid(struct kvm_vcpu *vcpu,
			    const struct kvmi_msg_hdr *msg,
			    const void *_req)
{
	const struct kvmi_get_cpuid *req = _req;
	struct kvmi_get_cpuid_reply rpl;
	int ec;

	memset(&rpl, 0, sizeof(rpl));

	ec = kvmi_cmd_get_cpuid(vcpu, req->function, req->index,
					&rpl.eax, &rpl.ebx, &rpl.ecx,
					&rpl.edx);

	return kvmi_msg_vcpu_reply(vcpu, msg, ec, &rpl, sizeof(rpl));
}

static int handle_get_xsave(struct kvm_vcpu *vcpu,
			    const struct kvmi_msg_hdr *msg, const void *req)
{
	struct kvmi_get_xsave_reply *rpl;
	size_t rpl_size = sizeof(*rpl) + sizeof(struct kvm_xsave);
	int ec = 0, err;

	rpl = kzalloc(rpl_size, GFP_KERNEL);

	if (!rpl) {
		ec = -KVM_ENOMEM;
	} else {
		struct kvm_xsave *area;

		area = (struct kvm_xsave *)&rpl->region[0];
		kvm_vcpu_ioctl_x86_get_xsave(vcpu, area);
	}

	err = kvmi_msg_vcpu_reply(vcpu, msg, ec, rpl, rpl_size);
	kfree(rpl);
	return err;
}

/*
 * These commands are executed on the vCPU thread. The receiving thread
 * saves the command into kvmi_vcpu.msg_buf[] and signals the vCPU to handle
 * the command (including sending back the reply).
 */
static int (*const msg_vcpu[])(struct kvm_vcpu *,
			       const struct kvmi_msg_hdr *, const void *) = {
	[KVMI_GET_GUEST_INFO]   = handle_get_guest_info,
	[KVMI_PAUSE_VCPU]       = handle_pause_vcpu,
	[KVMI_GET_REGISTERS]    = handle_get_registers,
	[KVMI_SET_REGISTERS]    = handle_set_registers,
	[KVMI_GET_PAGE_ACCESS]  = handle_get_page_access,
	[KVMI_SET_PAGE_ACCESS]  = handle_set_page_access,
	[KVMI_INJECT_EXCEPTION] = handle_inject_exception,
	[KVMI_CONTROL_EVENTS]   = handle_control_events,
	[KVMI_GET_CPUID]        = handle_get_cpuid,
	[KVMI_GET_XSAVE]        = handle_get_xsave,
};

void kvmi_msg_handle_vcpu_cmd(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvmi_msg_hdr *msg = (void *) ivcpu->msg_buf;
	u8 *req = ivcpu->msg_buf + sizeof(*msg);
	int err;

	err = msg_vcpu[msg->id](vcpu, msg, req);

	if (err)
		kvm_err("%s: id:%u (%s) err:%d\n", __func__, msg->id,
			id2str(msg->id), err);

	/*
	 * No error code is returned.
	 *
	 * The introspector gets its error code from the message handler
	 * or the socket is closed (and QEMU should reconnect).
	 */
}

static int kvmi_msg_recv_varlen(struct kvmi *ikvm, size_t(*cbk) (const void *),
				size_t min_n, size_t msg_size)
{
	size_t extra_n;
	u8 *extra_buf;
	int err;

	if (min_n > msg_size) {
		kvm_err("%s: got %zu bytes instead of min %zu\n",
			__func__, msg_size, min_n);
		return -EINVAL;
	}

	if (!min_n)
		return 0;

	err = kvmi_sock_read(ikvm, ikvm->msg_buf, min_n);

	extra_buf = ikvm->msg_buf + min_n;
	extra_n = msg_size - min_n;

	if (!err && extra_n) {
		if (cbk(ikvm->msg_buf) == msg_size)
			err = kvmi_sock_read(ikvm, extra_buf, extra_n);
		else
			err = -EINVAL;
	}

	return err;
}

static int kvmi_msg_recv_n(struct kvmi *ikvm, size_t n, size_t msg_size)
{
	if (n != msg_size) {
		kvm_err("%s: got %zu bytes instead of %zu\n",
			__func__, msg_size, n);
		return -EINVAL;
	}

	if (!n)
		return 0;

	return kvmi_sock_read(ikvm, ikvm->msg_buf, n);
}

static int kvmi_msg_recv(struct kvmi *ikvm, const struct kvmi_msg_hdr *msg)
{
	size_t (*cbk)(const void *) = msg_bytes[msg->id].cbk_full_size;
	size_t expected = msg_bytes[msg->id].size;

	if (cbk)
		return kvmi_msg_recv_varlen(ikvm, cbk, expected, msg->size);
	else
		return kvmi_msg_recv_n(ikvm, expected, msg->size);
}

struct vcpu_msg_hdr {
	__u16 vcpu;
	__u16 padding[3];
};

static int kvmi_msg_queue_to_vcpu(struct kvmi *ikvm,
				  const struct kvmi_msg_hdr *msg)
{
	struct vcpu_msg_hdr *vcpu_hdr = (struct vcpu_msg_hdr *)ikvm->msg_buf;
	struct kvmi_vcpu *ivcpu;
	struct kvm_vcpu *vcpu;

	if (msg->size < sizeof(*vcpu_hdr)) {
		kvm_err("%s: invalid vcpu message: %d\n", __func__, msg->size);
		return -EINVAL; /* ABI error */
	}

	vcpu = kvmi_get_vcpu(ikvm, vcpu_hdr->vcpu);

	if (!vcpu) {
		kvm_err("%s: invalid vcpu: %d\n", __func__, vcpu_hdr->vcpu);
		return kvmi_msg_reply(ikvm, msg, -KVM_EINVAL, NULL, 0);
	}

	ivcpu = vcpu->kvmi;

	if (!ivcpu) {
		kvm_err("%s: not introspected vcpu: %d\n",
			__func__, vcpu_hdr->vcpu);
		return kvmi_msg_reply(ikvm, msg, -KVM_EAGAIN, NULL, 0);
	}

	if (test_bit(REQ_CMD, &ivcpu->requests)) {
		kvm_err("%s: vcpu is busy: %d\n", __func__, vcpu_hdr->vcpu);
		return kvmi_msg_reply(ikvm, msg, -KVM_EBUSY, NULL, 0);
	}

	memcpy(ivcpu->msg_buf, msg, sizeof(*msg));
	memcpy(ivcpu->msg_buf + sizeof(*msg), ikvm->msg_buf, msg->size);

	kvmi_make_request(ivcpu, REQ_CMD);
	kvm_make_request(KVM_REQ_INTROSPECTION, vcpu);
	kvm_vcpu_kick(vcpu);

	return 0;
}

static bool kvmi_msg_dispatch_cmd(struct kvmi *ikvm,
				  const struct kvmi_msg_hdr *msg)
{
	int err = kvmi_msg_recv(ikvm, msg);

	if (err)
		goto out;

	if (!KVMI_ALLOWED_COMMAND(msg->id, ikvm->cmd_allow_mask)) {
		err = kvmi_msg_reply(ikvm, msg, -KVM_EPERM, NULL, 0);
		goto out;
	}

	if (msg_vcpu[msg->id])
		err = kvmi_msg_queue_to_vcpu(ikvm, msg);
	else
		err = msg_vm[msg->id](ikvm, msg, ikvm->msg_buf);

out:
	if (err)
		kvm_err("%s: id:%u (%s) err:%d\n", __func__, msg->id,
			id2str(msg->id), err);

	return (err == 0);
}

static bool handle_unsupported_msg(struct kvmi *ikvm,
				   const struct kvmi_msg_hdr *msg)
{
	int err;

	kvm_err("%s: %u\n", __func__, msg->id);

	err = consume_sock_bytes(ikvm, msg->size);

	if (!err)
		err = kvmi_msg_reply(ikvm, msg, -KVM_ENOSYS, NULL, 0);

	return (err == 0);
}

static bool kvmi_msg_dispatch(struct kvmi *ikvm)
{
	struct kvmi_msg_hdr msg;
	int err;

	err = kvmi_sock_read(ikvm, &msg, sizeof(msg));

	if (err) {
		kvm_err("%s: can't read\n", __func__);
		return false;
	}

	trace_kvmi_msg_dispatch(msg.id, msg.size);

	if (msg.id == KVMI_EVENT_REPLY)
		return kvmi_msg_dispatch_reply(ikvm, &msg);

	if (msg.id >= ARRAY_SIZE(msg_bytes)
	    || (!msg_vm[msg.id] && !msg_vcpu[msg.id]))
		return handle_unsupported_msg(ikvm, &msg);

	return kvmi_msg_dispatch_cmd(ikvm, &msg);
}

static void kvmi_sock_close(struct kvmi *ikvm)
{
	kvm_info("%s\n", __func__);

	write_lock(&ikvm->sock_lock);

	if (ikvm->sock) {
		kvm_info("Release the socket\n");
		sockfd_put(ikvm->sock);

		ikvm->sock = NULL;
	}

	write_unlock(&ikvm->sock_lock);
}

bool kvmi_msg_process(struct kvmi *ikvm)
{
	if (!kvmi_msg_dispatch(ikvm)) {
		kvmi_sock_close(ikvm);
		return false;
	}
	return true;
}

static void kvmi_setup_event(struct kvm_vcpu *vcpu, struct kvmi_event *ev,
			     u32 ev_id)
{
	memset(ev, 0, sizeof(*ev));
	ev->vcpu = vcpu->vcpu_id;
	ev->event = ev_id;
	kvm_arch_vcpu_ioctl_get_regs(vcpu, &ev->regs);
	kvm_arch_vcpu_ioctl_get_sregs(vcpu, &ev->sregs);
	ev->mode = kvmi_vcpu_mode(vcpu, &ev->sregs);
	kvmi_get_msrs(vcpu, ev);
}

static bool kvmi_send_event(struct kvm_vcpu *vcpu, u32 ev_id,
			    void *ev,  size_t ev_size,
			    void *rpl, size_t rpl_size)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvmi_event common;
	struct kvmi_msg_hdr h;
	struct kvec vec[3] = {
		{.iov_base = &h,      .iov_len = sizeof(h)     },
		{.iov_base = &common, .iov_len = sizeof(common)},
		{.iov_base = ev,      .iov_len = ev_size       },
	};
	size_t msg_size = sizeof(h) + sizeof(common) + ev_size;
	size_t n = ev_size ? ARRAY_SIZE(vec) : ARRAY_SIZE(vec)-1;

	memset(&h, 0, sizeof(h));
	h.id = KVMI_EVENT;
	h.seq = new_seq();
	h.size = msg_size - sizeof(h);

	kvmi_setup_event(vcpu, &common, ev_id);

	ivcpu->ev_rpl_ptr = rpl;
	ivcpu->ev_rpl_size = rpl_size;
	ivcpu->ev_seq = h.seq;
	ivcpu->ev_rpl_received = -1;
	WRITE_ONCE(ivcpu->ev_rpl_waiting, true);
	/* kvmi_vcpu_waiting_for_reply() */
	smp_wmb();

	trace_kvmi_send_event(ev_id);

	if (kvmi_sock_write(IKVM(vcpu->kvm), vec, n, msg_size) == 0)
		kvmi_handle_request(vcpu);

	return (ivcpu->ev_rpl_received >= 0);
}

u32 kvmi_msg_send_cr(struct kvm_vcpu *vcpu, u32 cr, u64 old_value,
		     u64 new_value, u64 *ret_value)
{
	struct kvmi_event_cr e;
	struct kvmi_event_cr_reply r;

	memset(&e, 0, sizeof(e));
	e.cr = cr;
	e.old_value = old_value;
	e.new_value = new_value;

	if (!kvmi_send_event(vcpu, KVMI_EVENT_CR, &e, sizeof(e),
				&r, sizeof(r))) {
		*ret_value = new_value;
		return KVMI_EVENT_ACTION_CONTINUE;
	}

	*ret_value = r.new_val;
	return IVCPU(vcpu)->ev_rpl.action;
}

u32 kvmi_msg_send_msr(struct kvm_vcpu *vcpu, u32 msr, u64 old_value,
		      u64 new_value, u64 *ret_value)
{
	struct kvmi_event_msr e;
	struct kvmi_event_msr_reply r;

	memset(&e, 0, sizeof(e));
	e.msr = msr;
	e.old_value = old_value;
	e.new_value = new_value;

	if (!kvmi_send_event(vcpu, KVMI_EVENT_MSR, &e, sizeof(e),
				&r, sizeof(r))) {
		*ret_value = new_value;
		return KVMI_EVENT_ACTION_CONTINUE;
	}

	*ret_value = r.new_val;
	return IVCPU(vcpu)->ev_rpl.action;
}

u32 kvmi_msg_send_xsetbv(struct kvm_vcpu *vcpu)
{
	if (!kvmi_send_event(vcpu, KVMI_EVENT_XSETBV, NULL, 0, NULL, 0))
		return KVMI_EVENT_ACTION_CONTINUE;

	return IVCPU(vcpu)->ev_rpl.action;
}

u32 kvmi_msg_send_bp(struct kvm_vcpu *vcpu, u64 gpa)
{
	struct kvmi_event_breakpoint e;

	memset(&e, 0, sizeof(e));
	e.gpa = gpa;

	if (!kvmi_send_event(vcpu, KVMI_EVENT_BREAKPOINT,
				&e, sizeof(e), NULL, 0))
		return KVMI_EVENT_ACTION_CONTINUE;

	return IVCPU(vcpu)->ev_rpl.action;
}

u32 kvmi_msg_send_hypercall(struct kvm_vcpu *vcpu)
{
	if (!kvmi_send_event(vcpu, KVMI_EVENT_HYPERCALL, NULL, 0, NULL, 0))
		return KVMI_EVENT_ACTION_CONTINUE;

	return IVCPU(vcpu)->ev_rpl.action;
}

u32 kvmi_msg_send_pf(struct kvm_vcpu *vcpu, u64 gpa, u64 gva, u32 mode,
		     bool *trap_access, u8 *ctx_data, u32 *ctx_size)
{
	u32 max_ctx_size = *ctx_size;
	struct kvmi_event_page_fault e;
	struct kvmi_event_page_fault_reply r;

	memset(&e, 0, sizeof(e));
	e.gpa = gpa;
	e.gva = gva;
	e.mode = mode;

	if (!kvmi_send_event(vcpu, KVMI_EVENT_PAGE_FAULT, &e, sizeof(e),
				&r, sizeof(r)))
		return KVMI_EVENT_ACTION_CONTINUE;

	*trap_access = r.trap_access;
	*ctx_size = 0;

	if (r.ctx_size <= max_ctx_size) {
		*ctx_size = min_t(u32, r.ctx_size, sizeof(r.ctx_data));
		if (*ctx_size)
			memcpy(ctx_data, r.ctx_data, *ctx_size);
	} else {
		kvm_err("%s: ctx_size (recv:%u max:%u)\n", __func__,
			r.ctx_size, *ctx_size);
		/*
		 * TODO: This is an ABI error.
		 * We should shutdown the socket?
		 */
	}

	return IVCPU(vcpu)->ev_rpl.action;
}

u32 kvmi_msg_send_trap(struct kvm_vcpu *vcpu, u32 vector, u32 type,
		       u32 error_code, u64 cr2)
{
	struct kvmi_event_trap e;

	memset(&e, 0, sizeof(e));
	e.vector = vector;
	e.type = type;
	e.error_code = error_code;
	e.cr2 = cr2;

	if (!kvmi_send_event(vcpu, KVMI_EVENT_TRAP, &e, sizeof(e), NULL, 0))
		return KVMI_EVENT_ACTION_CONTINUE;

	return IVCPU(vcpu)->ev_rpl.action;
}

u32 kvmi_msg_send_descriptor(struct kvm_vcpu *vcpu, u32 info,
			     u64 exit_qualification, u8 descriptor, u8 write)
{
	struct kvmi_event_descriptor e;

	memset(&e, 0, sizeof(e));
	e.descriptor = descriptor;
	e.write = write;

	if (cpu_has_vmx()) {
		e.arch.vmx.instr_info = info;
		e.arch.vmx.exit_qualification = exit_qualification;
	} else {
		e.arch.svm.exit_info = info;
	}

	if (!kvmi_send_event(vcpu, KVMI_EVENT_DESCRIPTOR,
				&e, sizeof(e), NULL, 0))
		return KVMI_EVENT_ACTION_CONTINUE;

	return IVCPU(vcpu)->ev_rpl.action;
}

u32 kvmi_msg_send_create_vcpu(struct kvm_vcpu *vcpu)
{
	if (!kvmi_send_event(vcpu, KVMI_EVENT_CREATE_VCPU, NULL, 0, NULL, 0))
		return KVMI_EVENT_ACTION_CONTINUE;

	return IVCPU(vcpu)->ev_rpl.action;
}

u32 kvmi_msg_send_pause_vcpu(struct kvm_vcpu *vcpu)
{
	if (!kvmi_send_event(vcpu, KVMI_EVENT_PAUSE_VCPU, NULL, 0, NULL, 0))
		return KVMI_EVENT_ACTION_CONTINUE;

	return IVCPU(vcpu)->ev_rpl.action;
}
