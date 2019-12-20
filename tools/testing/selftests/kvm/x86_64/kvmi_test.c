// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection tests
 *
 * Copyright (C) 2020, Bitdefender S.R.L.
 */

#define _GNU_SOURCE /* for program_invocation_short_name */
#include <sys/types.h>
#include <sys/socket.h>

#include "test_util.h"

#include "kvm_util.h"
#include "processor.h"
#include "../lib/kvm_util_internal.h"

#include "linux/kvm_para.h"
#include "linux/kvmi.h"

#define VCPU_ID         5

static int socket_pair[2];
#define Kvm_socket       socket_pair[0]
#define Userspace_socket socket_pair[1]

void setup_socket(void)
{
	int r;

	r = socketpair(AF_UNIX, SOCK_STREAM, 0, socket_pair);
	TEST_ASSERT(r == 0,
		"socketpair() failed, errno %d (%s)\n",
		errno, strerror(errno));
}

static void toggle_event_permission(struct kvm_vm *vm, __s32 id, bool allow)
{
	struct kvm_introspection_feature feat = {
		.allow = allow ? 1 : 0,
		.id = id
	};
	int r;

	r = ioctl(vm->fd, KVM_INTROSPECTION_EVENT, &feat);
	TEST_ASSERT(r == 0,
		"KVM_INTROSPECTION_EVENT failed, id %d, errno %d (%s)\n",
		id, errno, strerror(errno));
}

static void allow_event(struct kvm_vm *vm, __s32 event_id)
{
	toggle_event_permission(vm, event_id, true);
}

static void hook_introspection(struct kvm_vm *vm)
{
	__s32 all_IDs = -1;
	struct kvm_introspection_hook hook = {.fd = Kvm_socket};
	struct kvm_introspection_feature feat = {.allow = 1, .id = all_IDs};
	int r;

	r = ioctl(vm->fd, KVM_INTROSPECTION_HOOK, &hook);
	TEST_ASSERT(r == 0,
		"KVM_INTROSPECTION_HOOK failed, errno %d (%s)\n",
		errno, strerror(errno));

	r = ioctl(vm->fd, KVM_INTROSPECTION_COMMAND, &feat);
	TEST_ASSERT(r == 0,
		"KVM_INTROSPECTION_COMMAND failed, errno %d (%s)\n",
		errno, strerror(errno));

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
		"recv() failed, expected %d, result %d, errno %d (%s)\n",
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
		"Invalid message size %d, expected %d bytes (at least)\n",
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
		"send() failed, sending %d, result %d, errno %d (%s)\n",
		size, r, errno, strerror(errno));
}

static const char *kvm_strerror(int error)
{
	switch (error) {
	case KVM_ENOSYS:
		return "Invalid system call number";
	case KVM_EOPNOTSUPP:
		return "Operation not supported on transport endpoint";
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
			    size_t req_size, void *rpl, size_t rpl_size)
{
	int r;

	r = do_command(cmd_id, req, req_size, rpl, rpl_size);
	TEST_ASSERT(r == 0,
		    "Command %d failed, error %d (%s)\n",
		    cmd_id, -r, kvm_strerror(-r));
}

static void test_cmd_get_version(void)
{
	struct kvmi_get_version_reply rpl;
	struct kvmi_msg_hdr req;

	test_vm_command(KVMI_GET_VERSION, &req, sizeof(req), &rpl, sizeof(rpl));
	TEST_ASSERT(rpl.version == KVMI_VERSION,
		    "Unexpected KVMI version %d, expecting %d\n",
		    rpl.version, KVMI_VERSION);

	DEBUG("KVMI version: %u\n", rpl.version);
}

static int cmd_check_command(__u16 id)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vm_check_command cmd;
	} req = {};

	req.cmd.id = id;

	return do_command(KVMI_VM_CHECK_COMMAND, &req.hdr, sizeof(req), NULL,
			     0);
}

static void test_cmd_check_command(void)
{
	__u16 valid_id = KVMI_GET_VERSION;
	__u16 invalid_id = 0xffff;
	int r;

	r = cmd_check_command(valid_id);
	TEST_ASSERT(r == 0,
		"KVMI_VM_CHECK_COMMAND failed, error %d (%s)\n",
		-r, kvm_strerror(-r));

	r = cmd_check_command(invalid_id);
	TEST_ASSERT(r == -KVM_EINVAL,
		"KVMI_VM_CHECK_COMMAND didn't failed with -KVM_EINVAL, error %d (%s)\n",
		-r, kvm_strerror(-r));
}

static int cmd_check_event(__u16 id)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vm_check_event cmd;
	} req = {};

	req.cmd.id = id;

	return do_command(KVMI_VM_CHECK_EVENT, &req.hdr, sizeof(req), NULL, 0);
}

static void test_cmd_check_event(void)
{
	__u16 invalid_id = 0xffff;
	int r;

	r = cmd_check_event(invalid_id);
	TEST_ASSERT(r == -KVM_EINVAL,
		"KVMI_VM_CHECK_EVENT didn't failed with -KVM_EINVAL, error %d (%s)\n",
		-r, kvm_strerror(-r));
}

static void test_introspection(struct kvm_vm *vm)
{
	setup_socket();
	hook_introspection(vm);

	test_cmd_invalid();
	test_cmd_get_version();
	test_cmd_check_command();
	test_cmd_check_event();

	unhook_introspection(vm);
}

int main(int argc, char *argv[])
{
	struct kvm_vm *vm;

	if (!kvm_check_cap(KVM_CAP_INTROSPECTION)) {
		fprintf(stderr,
			"KVM_CAP_INTROSPECTION not available, skipping tests\n");
		exit(KSFT_SKIP);
	}

	vm = vm_create_default(VCPU_ID, 0, NULL);
	vcpu_set_cpuid(vm, VCPU_ID, kvm_get_supported_cpuid());

	test_introspection(vm);

	return 0;
}
