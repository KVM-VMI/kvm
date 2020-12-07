// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection tests
 *
 * Copyright (C) 2020, Bitdefender S.R.L.
 */

#define _GNU_SOURCE /* for program_invocation_short_name */
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <pthread.h>

#include "test_util.h"

#include "kvm_util.h"
#include "processor.h"
#include "../lib/kvm_util_internal.h"

#include "linux/kvm_para.h"
#include "linux/kvmi.h"
#include "asm/kvmi.h"

#define VCPU_ID 1

static int socket_pair[2];
#define Kvm_socket       socket_pair[0]
#define Userspace_socket socket_pair[1]

static int test_id;
static vm_vaddr_t test_gva;
static void *test_hva;
static vm_paddr_t test_gpa;

static int page_size;

struct vcpu_event {
	struct kvmi_event_hdr hdr;
	struct kvmi_vcpu_event common;
};

struct vcpu_reply {
	struct kvmi_msg_hdr hdr;
	struct kvmi_vcpu_hdr vcpu_hdr;
	struct kvmi_vcpu_event_reply reply;
};

struct vcpu_worker_data {
	struct kvm_vm *vm;
	int vcpu_id;
	int test_id;
};

enum {
	GUEST_TEST_NOOP = 0,
	GUEST_TEST_BP,
	GUEST_TEST_HYPERCALL,
};

#define GUEST_REQUEST_TEST()     GUEST_SYNC(0)
#define GUEST_SIGNAL_TEST_DONE() GUEST_SYNC(1)

#define HOST_SEND_TEST(uc)       (uc.cmd == UCALL_SYNC && uc.args[1] == 0)
#define HOST_TEST_DONE(uc)       (uc.cmd == UCALL_SYNC && uc.args[1] == 1)

static pthread_t start_vcpu_worker(struct vcpu_worker_data *data);
static void wait_vcpu_worker(pthread_t vcpu_thread);

static int guest_test_id(void)
{
	GUEST_REQUEST_TEST();
	return READ_ONCE(test_id);
}

static void guest_bp_test(void)
{
	asm volatile("int3");
}

static void guest_hypercall_test(void)
{
	asm volatile("mov $34, %rax");
	asm volatile("mov $24, %rdi");
	asm volatile("mov $0, %rsi");
	asm volatile(".byte 0x0f,0x01,0xc1");
}

static void guest_code(void)
{
	while (true) {
		switch (guest_test_id()) {
		case GUEST_TEST_NOOP:
			break;
		case GUEST_TEST_BP:
			guest_bp_test();
			break;
		case GUEST_TEST_HYPERCALL:
			guest_hypercall_test();
			break;
		}
		GUEST_SIGNAL_TEST_DONE();
	}
}

void setup_socket(void)
{
	int r;

	r = socketpair(AF_UNIX, SOCK_STREAM, 0, socket_pair);
	TEST_ASSERT(r == 0,
		"socketpair() failed, errno %d (%s)\n",
		errno, strerror(errno));
}

static void do_hook_ioctl(struct kvm_vm *vm, __s32 fd, int expected_err)
{
	struct kvm_introspection_hook hook = { .fd = fd, };
	int r;

	r = ioctl(vm->fd, KVM_INTROSPECTION_HOOK, &hook);
	TEST_ASSERT(r == 0 || errno == expected_err,
		"KVM_INTROSPECTION_HOOK failed, errno %d (%s), expected %d, fd %d\n",
		errno, strerror(errno), expected_err, fd);
}

static void set_perm(struct kvm_vm *vm, __s32 id, __u32 allow,
		     int expected_err, int ioctl_id,
		     const char *ioctl_str)
{
	struct kvm_introspection_feature feat = {
		.allow = allow,
		.id = id
	};
	int r;

	r = ioctl(vm->fd, ioctl_id, &feat);
	TEST_ASSERT(r == 0 || errno == expected_err,
		"%s failed, id %d, errno %d (%s), expected %d\n",
		ioctl_str, id, errno, strerror(errno), expected_err);
}

static void set_event_perm(struct kvm_vm *vm, __s32 id, __u32 allow,
			   int expected_err)
{
	set_perm(vm, id, allow, expected_err, KVM_INTROSPECTION_EVENT,
		 "KVM_INTROSPECTION_EVENT");
}

static void disallow_event(struct kvm_vm *vm, __s32 event_id)
{
	set_event_perm(vm, event_id, 0, 0);
}

static void allow_event(struct kvm_vm *vm, __s32 event_id)
{
	set_event_perm(vm, event_id, 1, 0);
}

static void set_command_perm(struct kvm_vm *vm, __s32 id, __u32 allow,
			     int expected_err)
{
	set_perm(vm, id, allow, expected_err, KVM_INTROSPECTION_COMMAND,
		 "KVM_INTROSPECTION_COMMAND");
}

static void disallow_command(struct kvm_vm *vm, __s32 id)
{
	set_command_perm(vm, id, 0, 0);
}

static void allow_command(struct kvm_vm *vm, __s32 id)
{
	set_command_perm(vm, id, 1, 0);
}

static void hook_introspection(struct kvm_vm *vm)
{
	struct vcpu_worker_data data = {.vm = vm, .vcpu_id = VCPU_ID };
	__u32 allow = 1, disallow = 0, allow_inval = 2;
	pthread_t vcpu_thread;
	__s32 all_IDs = -1;

	set_command_perm(vm, all_IDs, allow, EFAULT);
	set_event_perm(vm, all_IDs, allow, EFAULT);

	do_hook_ioctl(vm, -1, EINVAL);

	/*
	 * The last call failed "too late".
	 * We have to let the vCPU run and clean up its structures,
	 * otherwise the next call will fail with EEXIST.
	 */
	vcpu_thread = start_vcpu_worker(&data);
	wait_vcpu_worker(vcpu_thread);

	do_hook_ioctl(vm, Kvm_socket, 0);
	do_hook_ioctl(vm, Kvm_socket, EEXIST);

	set_command_perm(vm, KVMI_GET_VERSION, disallow, EPERM);
	set_command_perm(vm, KVMI_VM_CHECK_COMMAND, disallow, EPERM);
	set_command_perm(vm, KVMI_VM_CHECK_EVENT, disallow, EPERM);
	set_command_perm(vm, all_IDs, allow_inval, EINVAL);
	set_command_perm(vm, all_IDs, disallow, 0);
	set_command_perm(vm, all_IDs, allow, 0);

	set_event_perm(vm, all_IDs, allow_inval, EINVAL);
	set_event_perm(vm, all_IDs, disallow, 0);
	allow_event(vm, all_IDs);
}

static void unhook_introspection(struct kvm_vm *vm)
{
	int r;

	r = ioctl(vm->fd, KVM_INTROSPECTION_UNHOOK, NULL);
	TEST_ASSERT(r == 0,
		"KVM_INTROSPECTION_UNHOOK failed, errno %d (%s)\n",
		errno, strerror(errno));
}

static void receive_data(void *dest, size_t size)
{
	ssize_t r;

	r = recv(Userspace_socket, dest, size, MSG_WAITALL);
	TEST_ASSERT(r == size,
		"recv() failed, expected %zd, result %zd, errno %d (%s)\n",
		size, r, errno, strerror(errno));
}

static int receive_cmd_reply(struct kvmi_msg_hdr *req, void *rpl,
			     size_t rpl_size)
{
	struct kvmi_msg_hdr hdr;
	struct kvmi_error_code ec;

	receive_data(&hdr, sizeof(hdr));

	TEST_ASSERT(hdr.seq == req->seq,
		"Unexpected messages sequence 0x%x, expected 0x%x\n",
		hdr.seq, req->seq);

	TEST_ASSERT(hdr.size >= sizeof(ec),
		"Invalid message size %d, expected %zd bytes (at least)\n",
		hdr.size, sizeof(ec));

	receive_data(&ec, sizeof(ec));

	if (ec.err) {
		TEST_ASSERT(hdr.size == sizeof(ec),
			"Invalid command reply on error\n");
	} else {
		TEST_ASSERT(hdr.size == sizeof(ec) + rpl_size,
			"Invalid command reply\n");

		if (rpl && rpl_size)
			receive_data(rpl, rpl_size);
	}

	return ec.err;
}

static unsigned int new_seq(void)
{
	static unsigned int seq;

	return seq++;
}

static void send_message(int msg_id, struct kvmi_msg_hdr *hdr, size_t size)
{
	ssize_t r;

	hdr->id = msg_id;
	hdr->seq = new_seq();
	hdr->size = size - sizeof(*hdr);

	r = send(Userspace_socket, hdr, size, 0);
	TEST_ASSERT(r == size,
		"send() failed, sending %zd, result %zd, errno %d (%s)\n",
		size, r, errno, strerror(errno));
}

static const char *kvm_strerror(int error)
{
	switch (error) {
	case KVM_ENOSYS:
		return "Invalid system call number";
	case KVM_EOPNOTSUPP:
		return "Operation not supported on transport endpoint";
	case KVM_EAGAIN:
		return "Try again";
	default:
		return strerror(error);
	}
}

static int do_command(int cmd_id, struct kvmi_msg_hdr *req,
		      size_t req_size, void *rpl, size_t rpl_size)
{
	send_message(cmd_id, req, req_size);
	return receive_cmd_reply(req, rpl, rpl_size);
}

static void test_cmd_invalid(void)
{
	int invalid_msg_id = 0xffff;
	struct kvmi_msg_hdr req;
	int r;

	r = do_command(invalid_msg_id, &req, sizeof(req), NULL, 0);
	TEST_ASSERT(r == -KVM_ENOSYS,
		"Invalid command didn't failed with KVM_ENOSYS, error %d (%s)\n",
		-r, kvm_strerror(-r));
}

static void test_vm_command(int cmd_id, struct kvmi_msg_hdr *req,
			    size_t req_size, void *rpl, size_t rpl_size,
			    int expected_err)
{
	int r;

	r = do_command(cmd_id, req, req_size, rpl, rpl_size);
	TEST_ASSERT(r == expected_err,
		    "Command %d failed, error %d (%s) instead of %d (%s)\n",
		    cmd_id, -r, kvm_strerror(-r),
		    expected_err, kvm_strerror(expected_err));
}

static void cmd_vm_get_version(struct kvmi_get_version_reply *ver)
{
	struct kvmi_msg_hdr req;

	test_vm_command(KVMI_GET_VERSION, &req, sizeof(req), ver, sizeof(*ver), 0);
}

static void test_cmd_get_version(void)
{
	struct kvmi_get_version_reply rpl;

	cmd_vm_get_version(&rpl);
	TEST_ASSERT(rpl.version == KVMI_VERSION,
		    "Unexpected KVMI version %d, expecting %d\n",
		    rpl.version, KVMI_VERSION);

	pr_debug("KVMI version: %u\n", rpl.version);
	pr_debug("Max message size: %u\n", rpl.max_msg_size);
}

static void cmd_vm_check_command(__u16 id, int expected_err)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vm_check_command cmd;
	} req = {};

	req.cmd.id = id;

	test_vm_command(KVMI_VM_CHECK_COMMAND, &req.hdr, sizeof(req), NULL, 0,
			expected_err);
}

static void test_cmd_vm_check_command(struct kvm_vm *vm)
{
	__u16 valid_id = KVMI_VM_GET_INFO, invalid_id = 0xffff;

	cmd_vm_check_command(valid_id, 0);
	cmd_vm_check_command(invalid_id, -KVM_ENOENT);

	disallow_command(vm, valid_id);
	cmd_vm_check_command(valid_id, -KVM_EPERM);
	allow_command(vm, valid_id);
}

static void cmd_vm_check_event(__u16 id, int expected_err)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vm_check_event cmd;
	} req = {};

	req.cmd.id = id;

	test_vm_command(KVMI_VM_CHECK_EVENT, &req.hdr, sizeof(req), NULL, 0,
			expected_err);
}

static void test_cmd_vm_check_event(struct kvm_vm *vm)
{
	__u16 valid_id = KVMI_VM_EVENT_UNHOOK, invalid_id = 0xffff;

	cmd_vm_check_event(invalid_id, -KVM_ENOENT);
	cmd_vm_check_event(valid_id, 0);

	disallow_event(vm, valid_id);
	cmd_vm_check_event(valid_id, -KVM_EPERM);
	allow_event(vm, valid_id);
}

static void test_cmd_vm_get_info(void)
{
	struct kvmi_vm_get_info_reply rpl;
	struct kvmi_msg_hdr req;

	test_vm_command(KVMI_VM_GET_INFO, &req, sizeof(req), &rpl,
			sizeof(rpl), 0);
	TEST_ASSERT(rpl.vcpu_count == 1,
		    "Unexpected number of vCPU count %u\n",
		    rpl.vcpu_count);

	pr_debug("vcpu count: %u\n", rpl.vcpu_count);
}

static void trigger_event_unhook_notification(struct kvm_vm *vm)
{
	int r;

	r = ioctl(vm->fd, KVM_INTROSPECTION_PREUNHOOK, NULL);
	TEST_ASSERT(r == 0,
		"KVM_INTROSPECTION_PREUNHOOK failed, errno %d (%s)\n",
		errno, strerror(errno));
}

static void cmd_vm_control_events(__u16 event_id, __u8 enable,
				  int expected_err)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vm_control_events cmd;
	} req = {};

	req.cmd.event_id = event_id;
	req.cmd.enable = enable;

	test_vm_command(KVMI_VM_CONTROL_EVENTS, &req.hdr, sizeof(req),
			NULL, 0, expected_err);
}

static void enable_vm_event(__u16 event_id)
{
	cmd_vm_control_events(event_id, 1, 0);
}

static void disable_vm_event(__u16 event_id)
{
	cmd_vm_control_events(event_id, 0, 0);
}

static void receive_event(struct kvmi_msg_hdr *msg_hdr, u16 msg_id,
			  struct kvmi_event_hdr *ev_hdr, u16 event_id,
			  size_t ev_size)
{
	size_t to_read = ev_size;

	receive_data(msg_hdr, sizeof(*msg_hdr));

	TEST_ASSERT(msg_hdr->id == msg_id,
		"Unexpected messages id %d, expected %d\n",
		msg_hdr->id, msg_id);

	if (to_read > msg_hdr->size)
		to_read = msg_hdr->size;

	receive_data(ev_hdr, to_read);
	TEST_ASSERT(ev_hdr->event == event_id,
		"Unexpected event %d, expected %d\n",
		ev_hdr->event, event_id);

	TEST_ASSERT(msg_hdr->size == ev_size,
		"Invalid event size %d, expected %zd bytes\n",
		msg_hdr->size, ev_size);
}

static void receive_vm_event_unhook(void)
{
	struct kvmi_msg_hdr msg_hdr;
	struct kvmi_event_hdr ev_hdr;

	receive_event(&msg_hdr, KVMI_VM_EVENT,
		      &ev_hdr, KVMI_VM_EVENT_UNHOOK, sizeof(ev_hdr));
}

static void test_event_unhook(struct kvm_vm *vm)
{
	u16 id = KVMI_VM_EVENT_UNHOOK;

	enable_vm_event(id);

	trigger_event_unhook_notification(vm);

	receive_vm_event_unhook();

	disable_vm_event(id);
}

static void test_cmd_vm_control_events(struct kvm_vm *vm)
{
	__u16 id = KVMI_VM_EVENT_UNHOOK, invalid_id = 0xffff;
	__u8 enable = 1, enable_inval = 2;

	enable_vm_event(id);
	disable_vm_event(id);

	cmd_vm_control_events(id, enable_inval, -KVM_EINVAL);
	cmd_vm_control_events(invalid_id, enable, -KVM_EINVAL);

	disallow_event(vm, id);
	cmd_vm_control_events(id, enable, -KVM_EPERM);
	allow_event(vm, id);
}

static void cmd_vm_write_page(__u64 gpa, __u64 size, void *p,
			      int expected_err)
{
	struct kvmi_vm_write_physical *cmd;
	struct kvmi_msg_hdr *req;
	size_t req_size;

	req_size = sizeof(*req) + sizeof(*cmd) + size;
	req = calloc(1, req_size);

	cmd = (struct kvmi_vm_write_physical *)(req + 1);
	cmd->gpa = gpa;
	cmd->size = size;

	memcpy(cmd + 1, p, size);

	test_vm_command(KVMI_VM_WRITE_PHYSICAL, req, req_size, NULL, 0,
			expected_err);

	free(req);
}

static void write_guest_page(__u64 gpa, void *p)
{
	cmd_vm_write_page(gpa, page_size, p, 0);
}

static void write_with_invalid_arguments(__u64 gpa, __u64 size, void *p)
{
	cmd_vm_write_page(gpa, size, p, -KVM_EINVAL);
}

static void write_invalid_guest_page(struct kvm_vm *vm, void *p)
{
	__u64 gpa = vm->max_gfn << vm->page_shift;
	__u64 size = 1;

	cmd_vm_write_page(gpa, size, p, -KVM_ENOENT);
}

static void cmd_vm_read_page(__u64 gpa, __u64 size, void *p,
			     int expected_err)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vm_read_physical cmd;
	} req = { };

	req.cmd.gpa = gpa;
	req.cmd.size = size;

	test_vm_command(KVMI_VM_READ_PHYSICAL, &req.hdr, sizeof(req), p, size,
			expected_err);
}

static void read_guest_page(__u64 gpa, void *p)
{
	cmd_vm_read_page(gpa, page_size, p, 0);
}

static void read_with_invalid_arguments(__u64 gpa, __u64 size, void *p)
{
	cmd_vm_read_page(gpa, size, p, -KVM_EINVAL);
}

static void read_invalid_guest_page(struct kvm_vm *vm)
{
	__u64 gpa = vm->max_gfn << vm->page_shift;
	__u64 size = 1;

	cmd_vm_read_page(gpa, size, NULL, -KVM_ENOENT);
}

static void test_memory_access(struct kvm_vm *vm)
{
	void *pw, *pr;

	pw = malloc(page_size);
	TEST_ASSERT(pw, "Insufficient Memory\n");

	memset(pw, 1, page_size);

	write_guest_page(test_gpa, pw);
	TEST_ASSERT(memcmp(pw, test_hva, page_size) == 0,
		"Write page test failed");

	pr = malloc(page_size);
	TEST_ASSERT(pr, "Insufficient Memory\n");

	read_guest_page(test_gpa, pr);
	TEST_ASSERT(memcmp(pw, pr, page_size) == 0,
		"Read page test failed");

	read_with_invalid_arguments(test_gpa, 0, pr);
	write_with_invalid_arguments(test_gpa, 0, pw);
	write_invalid_guest_page(vm, pw);

	free(pw);
	free(pr);

	read_invalid_guest_page(vm);
}

static void *vcpu_worker(void *data)
{
	struct vcpu_worker_data *ctx = data;
	struct kvm_run *run;

	run = vcpu_state(ctx->vm, ctx->vcpu_id);

	while (true) {
		struct ucall uc;

		vcpu_run(ctx->vm, ctx->vcpu_id);

		TEST_ASSERT(run->exit_reason == KVM_EXIT_IO,
			"vcpu_run() failed, test_id %d, exit reason %u (%s)\n",
			ctx->test_id, run->exit_reason,
			exit_reason_str(run->exit_reason));

		TEST_ASSERT(get_ucall(ctx->vm, ctx->vcpu_id, &uc),
			"No guest request\n");

		if (HOST_SEND_TEST(uc)) {
			test_id = READ_ONCE(ctx->test_id);
			sync_global_to_guest(ctx->vm, test_id);
		} else if (HOST_TEST_DONE(uc)) {
			break;
		}
	}

	return NULL;
}

static pthread_t start_vcpu_worker(struct vcpu_worker_data *data)
{
	pthread_t thread_id;

	pthread_create(&thread_id, NULL, vcpu_worker, data);

	return thread_id;
}

static void wait_vcpu_worker(pthread_t vcpu_thread)
{
	pthread_join(vcpu_thread, NULL);
}

static int do_vcpu_command(struct kvm_vm *vm, int cmd_id,
			   struct kvmi_msg_hdr *req, size_t req_size,
			   void *rpl, size_t rpl_size)
{
	struct vcpu_worker_data data = {.vm = vm, .vcpu_id = VCPU_ID };
	pthread_t vcpu_thread;
	int r;

	vcpu_thread = start_vcpu_worker(&data);

	r = do_command(cmd_id, req, req_size, rpl, rpl_size);

	wait_vcpu_worker(vcpu_thread);
	return r;
}

static int __do_vcpu0_command(int cmd_id, struct kvmi_msg_hdr *req,
			      size_t req_size, void *rpl, size_t rpl_size)
{
	struct kvmi_vcpu_hdr *vcpu_hdr = (struct kvmi_vcpu_hdr *)(req + 1);

	vcpu_hdr->vcpu = 0;

	return do_command(cmd_id, req, req_size, rpl, rpl_size);
}

static int do_vcpu0_command(struct kvm_vm *vm, int cmd_id,
			    struct kvmi_msg_hdr *req, size_t req_size,
			    void *rpl, size_t rpl_size)
{
	struct kvmi_vcpu_hdr *vcpu_hdr = (struct kvmi_vcpu_hdr *)(req + 1);

	vcpu_hdr->vcpu = 0;

	return do_vcpu_command(vm, cmd_id, req, req_size, rpl, rpl_size);
}

static void test_vcpu0_command(struct kvm_vm *vm, int cmd_id,
			       struct kvmi_msg_hdr *req, size_t req_size,
			       void *rpl, size_t rpl_size,
			       int expected_err)
{
	int r;

	r = do_vcpu0_command(vm, cmd_id, req, req_size, rpl, rpl_size);
	TEST_ASSERT(r == expected_err,
		"Command %d failed, error %d (%s) instead of %d (%s)\n",
		cmd_id, -r, kvm_strerror(-r),
		expected_err, kvm_strerror(expected_err));
}

static void test_cmd_vcpu_get_info(struct kvm_vm *vm)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
	} req = {};
	struct kvmi_vcpu_get_info_reply rpl;
	int cmd_id = KVMI_VCPU_GET_INFO;

	test_vcpu0_command(vm, cmd_id, &req.hdr, sizeof(req),
			   &rpl, sizeof(rpl), 0);

	pr_debug("tsc_speed: %llu HZ\n", rpl.tsc_speed);

	req.vcpu_hdr.vcpu = 99;
	test_vm_command(cmd_id, &req.hdr, sizeof(req),
			&rpl, sizeof(rpl), -KVM_EINVAL);
}

static void cmd_vcpu_pause(__u8 wait, int expected_err)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vm_pause_vcpu cmd;
	} req = {};
	__u16 vcpu_idx = 0;

	req.cmd.wait = wait;
	req.cmd.vcpu = vcpu_idx;

	test_vm_command(KVMI_VM_PAUSE_VCPU, &req.hdr, sizeof(req), NULL, 0, expected_err);
}

static void pause_vcpu(void)
{
	cmd_vcpu_pause(1, 0);
}

static void reply_to_event(struct kvmi_msg_hdr *ev_hdr, struct vcpu_event *ev,
			   __u8 action, struct vcpu_reply *rpl, size_t rpl_size)
{
	ssize_t r;

	rpl->hdr.id = ev_hdr->id;
	rpl->hdr.seq = ev_hdr->seq;
	rpl->hdr.size = rpl_size - sizeof(rpl->hdr);

	rpl->vcpu_hdr.vcpu = ev->common.vcpu;

	rpl->reply.action = action;
	rpl->reply.event = ev->hdr.event;

	r = send(Userspace_socket, rpl, rpl_size, 0);
	TEST_ASSERT(r == rpl_size,
		"send() failed, sending %zd, result %zd, errno %d (%s)\n",
		rpl_size, r, errno, strerror(errno));
}

static void receive_vcpu_event(struct kvmi_msg_hdr *msg_hdr,
			       struct vcpu_event *ev,
			       size_t ev_size, u16 ev_id)
{
	receive_event(msg_hdr, KVMI_VCPU_EVENT,
		      &ev->hdr, ev_id, ev_size);
}

static void discard_pause_event(struct kvm_vm *vm)
{
	struct vcpu_worker_data data = {.vm = vm, .vcpu_id = VCPU_ID};
	struct vcpu_reply rpl = {};
	struct kvmi_msg_hdr hdr;
	pthread_t vcpu_thread;
	struct vcpu_event ev;

	vcpu_thread = start_vcpu_worker(&data);

	receive_vcpu_event(&hdr, &ev, sizeof(ev), KVMI_VCPU_EVENT_PAUSE);

	reply_to_event(&hdr, &ev, KVMI_EVENT_ACTION_CONTINUE,
			&rpl, sizeof(rpl));

	wait_vcpu_worker(vcpu_thread);
}

static void test_pause(struct kvm_vm *vm)
{
	__u8 no_wait = 0, wait = 1, wait_inval = 2;

	pause_vcpu();
	discard_pause_event(vm);

	cmd_vcpu_pause(wait, 0);
	discard_pause_event(vm);
	cmd_vcpu_pause(wait_inval, -KVM_EINVAL);

	disallow_event(vm, KVMI_VCPU_EVENT_PAUSE);
	cmd_vcpu_pause(no_wait, -KVM_EPERM);
	allow_event(vm, KVMI_VCPU_EVENT_PAUSE);
}

static void cmd_vcpu_control_event(struct kvm_vm *vm, __u16 event_id,
				   __u8 enable, int expected_err)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_control_events cmd;
	} req = {};

	req.cmd.event_id = event_id;
	req.cmd.enable = enable;

	test_vcpu0_command(vm, KVMI_VCPU_CONTROL_EVENTS,
			   &req.hdr, sizeof(req), NULL, 0,
			   expected_err);
}


static void enable_vcpu_event(struct kvm_vm *vm, __u16 event_id)
{
	cmd_vcpu_control_event(vm, event_id, 1, 0);
}

static void disable_vcpu_event(struct kvm_vm *vm, __u16 event_id)
{
	cmd_vcpu_control_event(vm, event_id, 0, 0);
}

static void test_cmd_vcpu_control_events(struct kvm_vm *vm)
{
	__u16 id = KVMI_VCPU_EVENT_PAUSE, invalid_id = 0xffff;
	__u8 enable = 1, enable_inval = 2;

	enable_vcpu_event(vm, id);
	disable_vcpu_event(vm, id);

	cmd_vcpu_control_event(vm, id, enable_inval, -KVM_EINVAL);
	cmd_vcpu_control_event(vm, invalid_id, enable, -KVM_EINVAL);

	disallow_event(vm, id);
	cmd_vcpu_control_event(vm, id, enable, -KVM_EPERM);
	allow_event(vm, id);

}

static void cmd_vcpu_get_registers(struct kvm_vm *vm, struct kvm_regs *regs)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_get_registers cmd;
	} req = {};
	struct kvmi_vcpu_get_registers_reply rpl;

	test_vcpu0_command(vm, KVMI_VCPU_GET_REGISTERS, &req.hdr, sizeof(req),
			   &rpl, sizeof(rpl), 0);

	memcpy(regs, &rpl.regs, sizeof(*regs));
}

static void test_invalid_vcpu_get_registers(struct kvm_vm *vm)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_get_registers cmd;
		__u32 msrs_idx[1];
	} req = {};
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_get_registers cmd;
	} *req_big;
	struct kvmi_vcpu_get_registers_reply rpl;
	struct kvmi_get_version_reply version;

	req.cmd.nmsrs = 1;
	req.cmd.msrs_idx[0] = 0xffffffff;
	test_vcpu0_command(vm, KVMI_VCPU_GET_REGISTERS,
			   &req.hdr, sizeof(req),
			   &rpl, sizeof(rpl), -KVM_EINVAL);

	cmd_vm_get_version(&version);

	req_big = calloc(1, version.max_msg_size);
	req_big->cmd.nmsrs = (version.max_msg_size - sizeof(*req_big)) / sizeof(__u32);
	test_vcpu0_command(vm, KVMI_VCPU_GET_REGISTERS,
			   &req.hdr, sizeof(req),
			   &rpl, sizeof(rpl), -KVM_EINVAL);
	free(req_big);
}

static void test_cmd_vcpu_get_registers(struct kvm_vm *vm)
{
	struct kvm_regs regs = {};

	cmd_vcpu_get_registers(vm, &regs);

	pr_debug("get_registers rip 0x%llx\n", regs.rip);

	test_invalid_vcpu_get_registers(vm);
}

static int __cmd_vcpu_set_registers(struct kvm_vm *vm,
				    struct kvm_regs *regs)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvm_regs regs;
	} req = {};

	memcpy(&req.regs, regs, sizeof(req.regs));

	return __do_vcpu0_command(KVMI_VCPU_SET_REGISTERS,
				  &req.hdr, sizeof(req), NULL, 0);
}

static void test_invalid_cmd_vcpu_set_registers(struct kvm_vm *vm)
{
	struct vcpu_worker_data data = {.vm = vm, .vcpu_id = VCPU_ID};
	pthread_t vcpu_thread;
	struct kvm_regs regs;
	int r;

	vcpu_thread = start_vcpu_worker(&data);

	r = __cmd_vcpu_set_registers(vm, &regs);

	wait_vcpu_worker(vcpu_thread);

	TEST_ASSERT(r == -KVM_EOPNOTSUPP,
		"KVMI_VCPU_SET_REGISTERS didn't failed with KVM_EOPNOTSUPP, error %d(%s)\n",
		-r, kvm_strerror(-r));
}

static void __set_registers(struct kvm_vm *vm,
			    struct kvm_regs *regs)
{
	int r;

	r = __cmd_vcpu_set_registers(vm, regs);
	TEST_ASSERT(r == 0,
		"KVMI_VCPU_SET_REGISTERS failed, error %d(%s)\n",
		-r, kvm_strerror(-r));
}

static void test_cmd_vcpu_set_registers(struct kvm_vm *vm)
{
	struct vcpu_worker_data data = {.vm = vm, .vcpu_id = VCPU_ID};
	__u16 event_id = KVMI_VCPU_EVENT_PAUSE;
	struct kvmi_msg_hdr hdr;
	pthread_t vcpu_thread;
	struct vcpu_event ev;
	struct vcpu_reply rpl = {};
	struct kvm_regs regs = {};

	cmd_vcpu_get_registers(vm, &regs);

	test_invalid_cmd_vcpu_set_registers(vm);

	pause_vcpu();

	vcpu_thread = start_vcpu_worker(&data);

	receive_vcpu_event(&hdr, &ev, sizeof(ev), event_id);

	__set_registers(vm, &ev.common.arch.regs);

	reply_to_event(&hdr, &ev, KVMI_EVENT_ACTION_CONTINUE,
			&rpl, sizeof(rpl));

	wait_vcpu_worker(vcpu_thread);
}

static void cmd_vcpu_get_cpuid(struct kvm_vm *vm,
			       __u32 function, __u32 index,
			       struct kvmi_vcpu_get_cpuid_reply *rpl)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_get_cpuid cmd;
	} req = {};

	req.cmd.function = function;
	req.cmd.index = index;

	test_vcpu0_command(vm, KVMI_VCPU_GET_CPUID, &req.hdr, sizeof(req),
			   rpl, sizeof(*rpl), 0);
}

static void test_cmd_vcpu_get_cpuid(struct kvm_vm *vm)
{
	struct kvmi_vcpu_get_cpuid_reply rpl = {};
	__u32 function = 0;
	__u32 index = 0;

	cmd_vcpu_get_cpuid(vm, function, index, &rpl);

	pr_debug("cpuid(%u, %u) => eax 0x%.8x, ebx 0x%.8x, ecx 0x%.8x, edx 0x%.8x\n",
	      function, index, rpl.eax, rpl.ebx, rpl.ecx, rpl.edx);
}

static void test_event_hypercall(struct kvm_vm *vm)
{
	struct vcpu_worker_data data = {
		.vm = vm,
		.vcpu_id = VCPU_ID,
		.test_id = GUEST_TEST_HYPERCALL,
	};
	struct kvmi_msg_hdr hdr;
	struct vcpu_event ev;
	struct vcpu_reply rpl = {};
	__u16 event_id = KVMI_VCPU_EVENT_HYPERCALL;
	pthread_t vcpu_thread;

	enable_vcpu_event(vm, event_id);

	vcpu_thread = start_vcpu_worker(&data);

	receive_vcpu_event(&hdr, &ev, sizeof(ev), event_id);

	pr_debug("Hypercall event, rip 0x%llx\n", ev.common.arch.regs.rip);

	reply_to_event(&hdr, &ev, KVMI_EVENT_ACTION_CONTINUE,
			&rpl, sizeof(rpl));

	wait_vcpu_worker(vcpu_thread);

	disable_vcpu_event(vm, event_id);
}

static void test_event_breakpoint(struct kvm_vm *vm)
{
	struct vcpu_worker_data data = {
		.vm = vm,
		.vcpu_id = VCPU_ID,
		.test_id = GUEST_TEST_BP,
	};
	struct kvmi_msg_hdr hdr;
	struct {
		struct vcpu_event vcpu_ev;
		struct kvmi_vcpu_event_breakpoint bp;
	} ev;
	struct vcpu_reply rpl = {};
	__u16 event_id = KVMI_VCPU_EVENT_BREAKPOINT;
	pthread_t vcpu_thread;

	enable_vcpu_event(vm, event_id);

	vcpu_thread = start_vcpu_worker(&data);

	receive_vcpu_event(&hdr, &ev.vcpu_ev, sizeof(ev), event_id);

	pr_debug("Breakpoint event, rip 0x%llx, len %u\n",
		ev.vcpu_ev.common.arch.regs.rip, ev.bp.insn_len);

	ev.vcpu_ev.common.arch.regs.rip += ev.bp.insn_len;
	__set_registers(vm, &ev.vcpu_ev.common.arch.regs);

	reply_to_event(&hdr, &ev.vcpu_ev, KVMI_EVENT_ACTION_RETRY,
			&rpl, sizeof(rpl));

	wait_vcpu_worker(vcpu_thread);

	disable_vcpu_event(vm, event_id);
}

static void test_introspection(struct kvm_vm *vm)
{
	srandom(time(0));
	setup_socket();
	hook_introspection(vm);

	test_cmd_invalid();
	test_cmd_get_version();
	test_cmd_vm_check_command(vm);
	test_cmd_vm_check_event(vm);
	test_cmd_vm_get_info();
	test_event_unhook(vm);
	test_cmd_vm_control_events(vm);
	test_memory_access(vm);
	test_cmd_vcpu_get_info(vm);
	test_pause(vm);
	test_cmd_vcpu_control_events(vm);
	test_cmd_vcpu_get_registers(vm);
	test_cmd_vcpu_set_registers(vm);
	test_cmd_vcpu_get_cpuid(vm);
	test_event_hypercall(vm);
	test_event_breakpoint(vm);

	unhook_introspection(vm);
}

static void setup_test_pages(struct kvm_vm *vm)
{
	test_gva = vm_vaddr_alloc(vm, page_size, KVM_UTIL_MIN_VADDR, 0, 0);
	sync_global_to_guest(vm, test_gva);

	test_hva = addr_gva2hva(vm, test_gva);
	test_gpa = addr_gva2gpa(vm, test_gva);
}

int main(int argc, char *argv[])
{
	struct kvm_vm *vm;

	if (!kvm_check_cap(KVM_CAP_INTROSPECTION)) {
		print_skip("KVM_CAP_INTROSPECTION not available");
		exit(KSFT_SKIP);
	}

	vm = vm_create_default(VCPU_ID, 0, guest_code);
	vcpu_set_cpuid(vm, VCPU_ID, kvm_get_supported_cpuid());

	page_size = getpagesize();
	setup_test_pages(vm);

	test_introspection(vm);

	kvm_vm_free(vm);
	return 0;
}
