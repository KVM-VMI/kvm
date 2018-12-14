// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection
 *
 * Copyright (C) 2017-2018 Bitdefender S.R.L.
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

static const char * const msg_IDs[] = {
	[KVMI_GET_VERSION]      = "KVMI_GET_VERSION",
	[KVMI_GET_GUEST_INFO]   = "KVMI_GET_GUEST_INFO",
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
	[KVMI_PAUSE_ALL_VCPUS]  = "KVMI_PAUSE_ALL_VCPUS",
	[KVMI_CONTROL_VM_EVENTS] = "KVMI_CONTROL_VM_EVENTS",
};

static bool is_cmd_valid(u16 id)
{
	return id < ARRAY_SIZE(msg_IDs);
}

static const char *id2str(u16 id)
{
	if (!is_cmd_valid(id) || msg_IDs[id] == NULL)
		return "unknown";

	return msg_IDs[id];
}

static const char * const ev_IDs[] = {
	[KVMI_EVENT_CR]			= "KVMI_EVENT_CR",
	[KVMI_EVENT_MSR]		= "KVMI_EVENT_MSR",
	[KVMI_EVENT_XSETBV]		= "KVMI_EVENT_XSETBV",
	[KVMI_EVENT_BREAKPOINT]		= "KVMI_EVENT_BREAKPOINT",
	[KVMI_EVENT_HYPERCALL]		= "KVMI_EVENT_HYPERCALL",
	[KVMI_EVENT_PF]			= "KVMI_EVENT_PF",
	[KVMI_EVENT_TRAP]		= "KVMI_EVENT_TRAP",
	[KVMI_EVENT_DESCRIPTOR]		= "KVMI_EVENT_DESCRIPTOR",
	[KVMI_EVENT_CREATE_VCPU]	= "KVMI_EVENT_CREATE_VCPU",
	[KVMI_EVENT_PAUSE_VCPU]		= "KVMI_EVENT_PAUSE_VCPU",
};

static bool is_ev_valid(u16 id)
{
	return id < ARRAY_SIZE(ev_IDs);
}

static const char *ev2str(u16 ev)
{
	if (!is_ev_valid(ev) || ev_IDs[ev] == NULL)
		return "unknown";

	return ev_IDs[ev];
}

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

static size_t sizeof_event_reply(const void *r)
{
	const struct kvmi_event_reply *req = r;

	switch (req->event) {
	case KVMI_EVENT_CR:
		return sizeof(*req) + sizeof(struct kvmi_event_cr_reply);
	case KVMI_EVENT_MSR:
		return sizeof(*req) + sizeof(struct kvmi_event_msr_reply);
	case KVMI_EVENT_PF:
		return sizeof(*req) + sizeof(struct kvmi_event_pf_reply);
	default:
		return sizeof(*req);
	}
}

static const struct {
	size_t size;
	size_t (*cbk_full_size)(const void *pld);
} msg_bytes[] = {
	[KVMI_GET_VERSION]      = { 0, NULL },
	[KVMI_GET_GUEST_INFO]   = { sizeof(struct kvmi_get_guest_info), NULL },
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
	[KVMI_PAUSE_ALL_VCPUS]  = { 0, NULL },
	[KVMI_EVENT_REPLY]	= { sizeof(struct kvmi_event_reply),
						sizeof_event_reply },
	[KVMI_CONTROL_VM_EVENTS] = { sizeof(struct kvmi_control_vm_events),
					NULL },
};

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

static struct kvmi_reply_cookie *
kvmi_find_cookie_by_seq(struct kvmi *ikvm, u32 seq)
{
	struct kvmi_reply_cookie *cookie;
	struct kvmi_reply_cookie *found = NULL;

	spin_lock(&ikvm->proto.rpl_lock);
	list_for_each_entry(cookie, &ikvm->proto.rpl_waiters, link) {
		if (cookie->seq == seq) {
			found = cookie;
			break;
		}
	}
	spin_unlock(&ikvm->proto.rpl_lock);

	return found;
}

static void kvmi_job_reply(struct kvm_vcpu *vcpu, void *ctx)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

	ivcpu->reply_waiting = false;
}

static int handle_event_reply(struct kvm_vcpu *vcpu,
			      const struct kvmi_msg_hdr *msg,
			      const void *_req)
{
	struct kvmi *ikvm = IKVM(vcpu->kvm);
	struct kvmi_reply_cookie *cookie;
	unsigned char *buf = (unsigned char *) _req;

	/* find cookie waiting for this reply */
	cookie = kvmi_find_cookie_by_seq(ikvm, msg->seq);
	if (!cookie) {
		kvmi_err(ikvm, "%s: unexpected event reply (seq = %u)\n",
			 __func__, msg->seq);
		return -ENOENT;
	}

	/* test message size against expected size */
	if (msg->size != sizeof(cookie->reply) + cookie->reply_size) {
		kvmi_err(ikvm, "%s: invalid reply size (recv = %zu, expected = %zu)\n",
			 __func__, (size_t) msg->size,
			 sizeof(cookie->reply) + cookie->reply_size);

		/* mark size error */
		cookie->error = -EINVAL;
		goto out_wakeup;
	}

	/* copy reply header */
	memcpy(&cookie->reply, buf, sizeof(cookie->reply));

	/* copy reply payload */
	if (cookie->reply_size != 0) {
		buf += sizeof(cookie->reply);
		memcpy(cookie->reply_data, buf, cookie->reply_size);
	}

	kvmi_debug(ikvm, "%s: vcpu %u waiting for %s reply, seq %d\n",
		   __func__, cookie->vcpu->vcpu_id, ev2str(cookie->reply.event),
		   cookie->seq);

	cookie->error = 0;

out_wakeup:
	kvmi_add_job(vcpu, kvmi_job_reply, NULL);

	return cookie->error;
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

static int kvmi_msg_vcpu_reply(struct kvm_vcpu *vcpu,
			       const struct kvmi_msg_hdr *msg, int err,
			       const void *rpl, size_t rpl_size)
{
	trace_kvmi_vcpu_reply(vcpu->vcpu_id, msg->id, msg->seq, err);

	return kvmi_msg_reply(IKVM(vcpu->kvm), msg, err, rpl, rpl_size);
}

static int handle_get_version(struct kvmi *ikvm,
			      const struct kvmi_msg_hdr *msg, const void *req)
{
	struct kvmi_get_version_reply rpl;

	memset(&rpl, 0, sizeof(rpl));
	rpl.version = KVMI_VERSION;
	rpl.commands = ikvm->cmd_allow_mask;
	rpl.events = ikvm->event_allow_mask;

	return kvmi_msg_vm_reply(ikvm, msg, 0, &rpl, sizeof(rpl));
}

static int handle_control_vm_events(struct kvmi *ikvm,
				    const struct kvmi_msg_hdr *msg,
				    const void *_req)
{
	const struct kvmi_control_vm_events *req = _req;
	u32 not_allowed = ~(ikvm->event_allow_mask & KVMI_KNOWN_VM_EVENTS);
	int ec;

	if (req->events & ~KVMI_KNOWN_VM_EVENTS)
		ec = -KVM_EINVAL;
	else if (req->events & not_allowed)
		ec = -KVM_EPERM;
	else
		ec = kvmi_cmd_control_vm_events(ikvm, req->events);

	return kvmi_msg_vm_reply(ikvm, msg, ec, NULL, 0);
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
				      kvmi_msg_vm_reply, msg);
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

	return kvmi_msg_vm_reply(ikvm, msg, ec, NULL, 0);
}

static int handle_get_map_token(struct kvmi *ikvm,
				const struct kvmi_msg_hdr *msg,
				const void *_req)
{
	struct kvmi_get_map_token_reply rpl;
	int ec;

	memset(&rpl, 0, sizeof(rpl));
	ec = kvmi_cmd_alloc_token(ikvm->kvm, &rpl.token);

	return kvmi_msg_vm_reply(ikvm, msg, ec, &rpl, sizeof(rpl));
}

static int handle_pause_all_vcpus(struct kvmi *ikvm,
				  const struct kvmi_msg_hdr *msg,
				  const void *req)
{
	struct kvmi_pause_all_vcpus_reply rpl;
	int ec;

	memset(&rpl, 0, sizeof(rpl));
	ec = kvmi_cmd_pause_all_vcpus(ikvm->kvm, &rpl.vcpu_count);

	return kvmi_msg_vm_reply(ikvm, msg, ec, &rpl, sizeof(rpl));
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
	[KVMI_PAUSE_ALL_VCPUS]  = handle_pause_all_vcpus,
	[KVMI_CONTROL_VM_EVENTS] = handle_control_vm_events,
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
		ec = -KVM_EINVAL;
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
	u16 k, n = req->count;
	u8 unknown_bits = ~(KVMI_PAGE_ACCESS_R | KVMI_PAGE_ACCESS_W
				| KVMI_PAGE_ACCESS_X);
	int ec = 0;

	if (req->view != 0 && !kvm_eptp_switching_supported) {
		ec = -KVM_EINVAL;
		goto out;
	}

	if (req->view != 0) { /* TODO */
		ec = -KVM_EINVAL;
		goto out;
	}

	for (k = 0; k < n && ec == 0; k++) {
		u64 gpa   = req->entries[k].gpa;
		u8 access = req->entries[k].access;

		if (access & unknown_bits)
			ec = -KVM_EINVAL;
		else
			ec = kvmi_cmd_set_page_access(vcpu, gpa, access);
	}

out:
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
	int ec;

	if (req->events & ~KVMI_KNOWN_VCPU_EVENTS)
		ec = -KVM_EINVAL;
	else if (req->events & not_allowed)
		ec = -KVM_EPERM;
	else
		ec = kvmi_cmd_control_events(vcpu, req->events);

	return kvmi_msg_vcpu_reply(vcpu, msg, ec, NULL, 0);
}

static int handle_control_cr(struct kvm_vcpu *vcpu,
			     const struct kvmi_msg_hdr *msg, const void *_req)
{
	const struct kvmi_control_cr *req = _req;
	int ec;

	ec = kvmi_cmd_control_cr(vcpu, req->enable, req->cr);

	return kvmi_msg_vcpu_reply(vcpu, msg, ec, NULL, 0);
}

static int handle_control_msr(struct kvm_vcpu *vcpu,
			      const struct kvmi_msg_hdr *msg, const void *_req)
{
	const struct kvmi_control_msr *req = _req;
	int ec;

	ec = kvmi_cmd_control_msr(vcpu, req->enable, req->msr);

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
	[KVMI_GET_REGISTERS]    = handle_get_registers,
	[KVMI_SET_REGISTERS]    = handle_set_registers,
	[KVMI_GET_PAGE_ACCESS]  = handle_get_page_access,
	[KVMI_SET_PAGE_ACCESS]  = handle_set_page_access,
	[KVMI_INJECT_EXCEPTION] = handle_inject_exception,
	[KVMI_CONTROL_EVENTS]   = handle_control_events,
	[KVMI_CONTROL_CR]       = handle_control_cr,
	[KVMI_CONTROL_MSR]      = handle_control_msr,
	[KVMI_GET_CPUID]        = handle_get_cpuid,
	[KVMI_GET_XSAVE]        = handle_get_xsave,
	[KVMI_EVENT_REPLY]	= handle_event_reply,
};

static void kvmi_job_vcpu_cmd(struct kvm_vcpu *vcpu, void *ctx)
{
	struct kvmi_msg_hdr *msg = ctx;
	unsigned char *pld;
	int err;

	pld = (unsigned char *) msg + sizeof(*msg);

	err = msg_vcpu[msg->id](vcpu, msg, pld);

	if (err)
		kvmi_err(IKVM(vcpu->kvm),
			 "%s: cmd id: %u (%s), err: %d\n", __func__,
			 msg->id, id2str(msg->id), err);

	kfree(ctx);
}

static int kvmi_msg_queue_to_vcpu(struct kvm_vcpu *vcpu,
				  const struct kvmi_msg_hdr *msg)
{
	return kvmi_add_job(vcpu, kvmi_job_vcpu_cmd, (void *)msg);
}

static struct kvmi_msg_hdr *kvmi_msg_recv(struct kvmi *ikvm)
{
	struct kvmi_msg_hdr *msg = NULL;
	struct kvmi_msg_hdr *larger_msg;
	unsigned char *buf;
	size_t (*cbk)(const void *pld);
	size_t bufsize, fixed, dynamic;
	int err = 0;

	/* alloc buffer for the message */
	bufsize = roundup(KVMI_MSG_SIZE, PAGE_SIZE);
	msg = kmalloc(bufsize, GFP_KERNEL);
	if (!msg) {
		kvmi_err(ikvm, "%s: could not allocate %zu bytes\n",
			 __func__, bufsize);
		goto out;
	}

	/* read message header */
	err = kvmi_sock_read(ikvm, msg, sizeof(*msg));
	if (err)
		goto out;

	/* validate message id */
	if (!is_cmd_valid(msg->id)) {
		kvmi_err(ikvm, "%s: invalid message ID (%d)\n",
			 __func__, msg->id);
		goto out;
	}

	/* check fixed length */
	fixed = msg_bytes[msg->id].size;
	if (sizeof(*msg) + fixed > bufsize) {
		bufsize = roundup(sizeof(*msg) + fixed, PAGE_SIZE);
		larger_msg = krealloc(msg, bufsize, GFP_KERNEL);
		if (!larger_msg) {
			kvmi_err(ikvm, "%s: could not allocate %zu bytes\n",
				 __func__, bufsize);
			goto out;
		} else
			msg = larger_msg;
	}

	cbk = msg_bytes[msg->id].cbk_full_size;
	if (cbk) {
		if (fixed > msg->size) {
			kvmi_err(ikvm, "%s: %s, got %zu bytes instead of min %zu\n",
				 __func__, id2str(msg->id), (size_t) msg->size,
				 fixed);
			goto out;
		}
	} else if (fixed != msg->size) {
		kvmi_err(ikvm, "%s: %s, got %zu bytes instead of expected %zu\n",
			 __func__, id2str(msg->id), (size_t) msg->size, fixed);
		goto out;
	}

	/* bail out if nothing more to read */
	if (fixed == 0)
		return msg;

	/* read fixed chunk */
	buf = (unsigned char *) msg + sizeof(*msg);
	err = kvmi_sock_read(ikvm, buf, fixed);
	if (err)
		goto out;

	/* bail out if nothing more to read */
	if (!cbk)
		return msg;

	/* check dynamic length */
	dynamic = cbk(buf);
	if (sizeof(*msg) + dynamic > bufsize) {
		bufsize = roundup(sizeof(*msg) + dynamic, PAGE_SIZE);
		larger_msg = krealloc(msg, bufsize, GFP_KERNEL);
		if (!larger_msg) {
			kvmi_err(ikvm, "%s: could not allocate %zu bytes\n",
				 __func__, bufsize);
			goto out;
		} else
			msg = larger_msg;
	}

	if (dynamic != msg->size) {
		kvmi_err(ikvm, "%s: msg %s, got %zu bytes instead of expected %zu\n",
			 __func__, id2str(msg->id),
			 (size_t) msg->size, dynamic);
		goto out;
	}

	/* read the rest of the buf */
	buf = (unsigned char *) msg + sizeof(*msg) + fixed;
	err = kvmi_sock_read(ikvm, buf, dynamic - fixed);
	if (err)
		goto out;

	/* message fully read */
	return msg;

out:
	kfree(msg);

	return NULL;
}

static bool kvmi_msg_dispatch_cmd(struct kvmi *ikvm,
	const struct kvmi_msg_hdr *msg, bool *queued)
{
	unsigned char *pld;
	__u16 vcpu_id;
	struct kvm_vcpu *vcpu;
	int err;

	if (!KVMI_ALLOWED_COMMAND(msg->id, ikvm->cmd_allow_mask)) {
		kvmi_warn(ikvm, "%s: command not allowed: %s\n",
			__func__, id2str(msg->id));

		err = kvmi_msg_vm_reply(ikvm, msg, -KVM_EACCES, NULL, 0);
		goto out;
	}

	pld = (unsigned char *) msg + sizeof(*msg);

	if (msg_vcpu[msg->id]) {
		/* first member of the structure will be VCPU ID !!! */
		vcpu_id = *(__u16 *)pld;

		trace_kvmi_vcpu_command(vcpu_id, msg->id, msg->seq);

		vcpu = kvmi_get_vcpu(ikvm, vcpu_id);
		if (!vcpu) {
			err = kvmi_msg_vm_reply(ikvm, msg, -KVM_EINVAL,
						NULL, 0);
		} else if (unlikely(vcpu->arch.mp_state
				== KVM_MP_STATE_UNINITIALIZED)) {
			err = kvmi_msg_vm_reply(ikvm, msg, -KVM_EAGAIN,
						NULL, 0);
		} else {
			/* the VCPU will be free the message !!! */
			err = kvmi_msg_queue_to_vcpu(vcpu, msg);
			if (!err)
				*queued = true;
		}
	} else {
		trace_kvmi_vm_command(msg->id, msg->seq);

		/* directly execute callback for this message type */
		err = msg_vm[msg->id](ikvm, msg, pld);
	}

out:
	if (err)
		kvmi_err(ikvm, "%s: msg id: %u (%s), err: %d\n", __func__,
			 msg->id, id2str(msg->id), err);

	return (err == 0);
}

static bool handle_unsupported_msg(struct kvmi *ikvm,
				   const struct kvmi_msg_hdr *msg)
{
	int err;

	kvmi_warn(ikvm, "%s: %d (%s)\n", __func__, msg->id, id2str(msg->id));

	err = kvmi_msg_vm_reply(ikvm, msg, -KVM_ENOSYS, NULL, 0);
	if (err)
		kvmi_err(ikvm, "%s: msg id: %u (%s), err: %d\n",
			 __func__, msg->id, id2str(msg->id), err);

	return (err == 0);
}

static bool kvmi_msg_dispatch_reply(struct kvmi *ikvm,
				    const struct kvmi_msg_hdr *msg,
				    bool *queued)
{
	unsigned char *buf = (unsigned char *) msg + sizeof(*msg);
	struct kvmi_event_reply *rpl = (struct kvmi_event_reply *) buf;
	struct kvmi_reply_cookie *cookie;
	int err;

	trace_kvmi_event_reply(rpl->event, msg->seq, rpl->action);

	/* find cookie waiting for this reply */
	cookie = kvmi_find_cookie_by_seq(ikvm, msg->seq);
	if (!cookie) {
		kvmi_err(ikvm, "%s: unexpected event reply (seq = %u)\n",
			 __func__, msg->seq);
		return false;
	}

	/* dispatch the message to the cookie's VCPU */
	err = kvmi_msg_queue_to_vcpu(cookie->vcpu, msg);
	if (!err)
		*queued = true;

	return (err == 0);
}

bool kvmi_msg_process(struct kvmi *ikvm)
{
	struct kvmi_msg_hdr *msg;
	bool queued = false;
	bool success;

	/* this will allocate buffer & fully read the message !!! */
	msg = kvmi_msg_recv(ikvm);
	if (!msg)
		return false;

	if (msg->id == KVMI_EVENT_REPLY)
		success = kvmi_msg_dispatch_reply(ikvm, msg, &queued);
	else if (msg->id >= ARRAY_SIZE(msg_bytes) ||
		(!msg_vm[msg->id] && !msg_vcpu[msg->id]))
		success = handle_unsupported_msg(ikvm, msg);
	else
		success = kvmi_msg_dispatch_cmd(ikvm, msg, &queued);

	if (!queued)
		kfree(msg);

	return success;
}

static void kvmi_setup_event(struct kvm_vcpu *vcpu, struct kvmi_event *ev,
			     u32 ev_id)
{
	memset(ev, 0, sizeof(*ev));

	ev->vcpu = vcpu->vcpu_id;
	ev->event = ev_id;

	kvm_arch_vcpu_get_regs(vcpu, &ev->regs);
	kvm_arch_vcpu_get_sregs(vcpu, &ev->sregs);
	ev->mode = kvmi_vcpu_mode(vcpu, &ev->sregs);
	kvmi_get_msrs(vcpu, ev);
}

static inline u32 new_seq(struct kvmi *ikvm)
{
	return atomic_inc_return(&ikvm->proto.ev_seq);
}

static int kvmi_send_event(struct kvm_vcpu *vcpu, u32 ev_id,
			   void *ev,  size_t ev_size,
			   void *rpl, size_t rpl_size,
			   int *action)
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

	struct kvmi *ikvm = IKVM(vcpu->kvm);
	struct kvmi_reply_cookie cookie;
	int err;

	memset(&hdr, 0, sizeof(hdr));
	hdr.id = KVMI_EVENT;
	hdr.seq = new_seq(ikvm);
	hdr.size = msg_size - sizeof(hdr);

	kvmi_setup_event(vcpu, &common, ev_id);

	memset(&cookie, 0, sizeof(cookie));
	cookie.vcpu = vcpu;
	cookie.seq = hdr.seq;
	cookie.reply.event = ev_id;
	cookie.reply_data = rpl;
	cookie.reply_size = rpl_size;
	cookie.error = -EINTR;
	INIT_LIST_HEAD(&cookie.link);

	/*
	 * add cookie to list even before sending the event !!!
	 * otherwise the reply may come before the cookie and find nothing
	 */
	spin_lock(&ikvm->proto.rpl_lock);
	list_add(&cookie.link, &ikvm->proto.rpl_waiters);
	spin_unlock(&ikvm->proto.rpl_lock);

	trace_kvmi_event(vcpu->vcpu_id, common.event, hdr.seq);

	err = kvmi_sock_write(IKVM(vcpu->kvm), vec, n, msg_size);
	if (err)
		goto out;

	IVCPU(vcpu)->reply_waiting = true;
	err = kvmi_run_jobs_and_wait(vcpu);
	if (err)
		goto out;

	kvmi_post_reply(vcpu); /* move me - useless on errors */
	err = cookie.error;
	if (err)
		goto out;

	*action = cookie.reply.action;

out:
	spin_lock(&ikvm->proto.rpl_lock);
	list_del(&cookie.link);
	spin_unlock(&ikvm->proto.rpl_lock);

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

	memset(&common, 0, sizeof(common));
	common.event = KVMI_EVENT_UNHOOK;

	trace_kvmi_event(0, hdr.id, hdr.seq);

	return kvmi_sock_write(ikvm, vec, n, msg_size);
}

u32 kvmi_msg_send_cr(struct kvm_vcpu *vcpu, u32 cr, u64 old_value,
		     u64 new_value, u64 *ret_value)
{
	struct kvmi_event_cr e;
	struct kvmi_event_cr_reply r;
	int err, action;

	memset(&e, 0, sizeof(e));
	e.cr = cr;
	e.old_value = old_value;
	e.new_value = new_value;

	err = kvmi_send_event(vcpu, KVMI_EVENT_CR, &e, sizeof(e),
			      &r, sizeof(r), &action);
	if (err) {
		*ret_value = new_value;
		return KVMI_EVENT_ACTION_CONTINUE;
	}

	*ret_value = r.new_val;
	return action;
}

u32 kvmi_msg_send_msr(struct kvm_vcpu *vcpu, u32 msr, u64 old_value,
		      u64 new_value, u64 *ret_value)
{
	struct kvmi_event_msr e;
	struct kvmi_event_msr_reply r;
	int err, action;

	memset(&e, 0, sizeof(e));
	e.msr = msr;
	e.old_value = old_value;
	e.new_value = new_value;

	err = kvmi_send_event(vcpu, KVMI_EVENT_MSR, &e, sizeof(e),
			      &r, sizeof(r), &action);
	if (err) {
		*ret_value = new_value;
		return KVMI_EVENT_ACTION_CONTINUE;
	}

	*ret_value = r.new_val;
	return action;
}

u32 kvmi_msg_send_xsetbv(struct kvm_vcpu *vcpu)
{
	int err, action;

	err = kvmi_send_event(vcpu, KVMI_EVENT_XSETBV, NULL, 0,
			      NULL, 0, &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	return action;
}

u32 kvmi_msg_send_bp(struct kvm_vcpu *vcpu, u64 gpa)
{
	struct kvmi_event_breakpoint e;
	int err, action;

	memset(&e, 0, sizeof(e));
	e.gpa = gpa;

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

u32 kvmi_msg_send_pf(struct kvm_vcpu *vcpu, u64 gpa, u64 gva, u32 mode,
	bool *singlestep, bool *rep_complete, u8 *ctx_data, u32 *ctx_size)
{
	u32 max_ctx_size = *ctx_size;
	struct kvmi_event_pf e;
	struct kvmi_event_pf_reply r;
	int err, action;

	memset(&e, 0, sizeof(e));
	e.gpa = gpa;
	e.gva = gva;
	e.mode = mode;

	err = kvmi_send_event(vcpu, KVMI_EVENT_PF, &e, sizeof(e),
			      &r, sizeof(r), &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

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
	if (*ctx_size)
		memcpy(ctx_data, r.ctx_data, *ctx_size);

	return action;
}

u32 kvmi_msg_send_trap(struct kvm_vcpu *vcpu, u32 vector, u32 type,
		       u32 error_code, u64 cr2)
{
	struct kvmi_event_trap e;
	int err, action;

	memset(&e, 0, sizeof(e));
	e.vector = vector;
	e.type = type;
	e.error_code = error_code;
	e.cr2 = cr2;

	err = kvmi_send_event(vcpu, KVMI_EVENT_TRAP, &e, sizeof(e),
			      NULL, 0, &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	return action;
}

u32 kvmi_msg_send_descriptor(struct kvm_vcpu *vcpu, u32 info,
			     u64 exit_qualification, u8 descriptor, u8 write)
{
	struct kvmi_event_descriptor e;
	int err, action;

	memset(&e, 0, sizeof(e));
	e.descriptor = descriptor;
	e.write = write;

	if (cpu_has_vmx()) {
		e.arch.vmx.instr_info = info;
		e.arch.vmx.exit_qualification = exit_qualification;
	} else {
		e.arch.svm.exit_info = info;
	}

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

