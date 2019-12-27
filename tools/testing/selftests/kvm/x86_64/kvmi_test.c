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

static void test_introspection(struct kvm_vm *vm)
{
	setup_socket();
	hook_introspection(vm);
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
