// SPDX-License-Identifier: GPL-2.0
/*
 * KVM Introspection
 *
 * Copyright (C) 2017-2020 Bitdefender S.R.L.
 *
 */
#include <linux/kthread.h>
#include "kvmi_int.h"

#define KVMI_NUM_COMMANDS __cmp((int)KVMI_NEXT_VM_MESSAGE, \
				(int)KVMI_NEXT_VCPU_MESSAGE, >)
#define KVMI_NUM_EVENTS   __cmp((int)KVMI_NEXT_VM_EVENT, \
				(int)KVMI_NEXT_VCPU_EVENT, >)

#define KVMI_MSG_SIZE_ALLOC (sizeof(struct kvmi_msg_hdr) + KVMI_MAX_MSG_SIZE)

static DECLARE_BITMAP(Kvmi_always_allowed_commands, KVMI_NUM_COMMANDS);
static DECLARE_BITMAP(Kvmi_known_events, KVMI_NUM_EVENTS);
static DECLARE_BITMAP(Kvmi_known_vm_events, KVMI_NUM_EVENTS);
static DECLARE_BITMAP(Kvmi_known_vcpu_events, KVMI_NUM_EVENTS);

static struct kmem_cache *msg_cache;

void *kvmi_msg_alloc(void)
{
	return kmem_cache_zalloc(msg_cache, GFP_KERNEL);
}

void kvmi_msg_free(void *addr)
{
	if (addr)
		kmem_cache_free(msg_cache, addr);
}

static void kvmi_cache_destroy(void)
{
	kmem_cache_destroy(msg_cache);
	msg_cache = NULL;
}

static int kvmi_cache_create(void)
{
	msg_cache = kmem_cache_create("kvmi_msg", KVMI_MSG_SIZE_ALLOC,
				      4096, SLAB_ACCOUNT, NULL);

	if (!msg_cache) {
		kvmi_cache_destroy();

		return -1;
	}

	return 0;
}

bool kvmi_is_command_allowed(struct kvm_introspection *kvmi, u16 id)
{
	return id < KVMI_NUM_COMMANDS && test_bit(id, kvmi->cmd_allow_mask);
}

bool kvmi_is_event_allowed(struct kvm_introspection *kvmi, u16 id)
{
	return id < KVMI_NUM_EVENTS && test_bit(id, kvmi->event_allow_mask);
}

bool kvmi_is_known_event(u16 id)
{
	return id < KVMI_NUM_EVENTS && test_bit(id, Kvmi_known_events);
}

static void kvmi_init_always_allowed_commands(void)
{
	bitmap_zero(Kvmi_always_allowed_commands, KVMI_NUM_COMMANDS);
	set_bit(KVMI_GET_VERSION, Kvmi_always_allowed_commands);
	set_bit(KVMI_VM_CHECK_COMMAND, Kvmi_always_allowed_commands);
	set_bit(KVMI_VM_CHECK_EVENT, Kvmi_always_allowed_commands);
}

static void kvmi_init_known_events(void)
{
	bitmap_zero(Kvmi_known_vm_events, KVMI_NUM_EVENTS);
	set_bit(KVMI_VM_EVENT_UNHOOK, Kvmi_known_vm_events);

	bitmap_zero(Kvmi_known_vcpu_events, KVMI_NUM_EVENTS);
	kvmi_arch_init_vcpu_events_mask(Kvmi_known_vcpu_events);

	bitmap_or(Kvmi_known_events, Kvmi_known_vm_events,
		  Kvmi_known_vcpu_events, KVMI_NUM_EVENTS);
}

int kvmi_init(void)
{
	kvmi_init_always_allowed_commands();
	kvmi_init_known_events();

	return kvmi_cache_create();
}

int kvmi_version(void)
{
	return KVMI_VERSION;
}

void kvmi_uninit(void)
{
	kvmi_cache_destroy();
}

static void kvmi_free(struct kvm *kvm)
{
	bitmap_free(kvm->kvmi->cmd_allow_mask);
	bitmap_free(kvm->kvmi->event_allow_mask);

	kfree(kvm->kvmi);
	kvm->kvmi = NULL;
}

static struct kvm_introspection *
kvmi_alloc(struct kvm *kvm, const struct kvm_introspection_hook *hook)
{
	struct kvm_introspection *kvmi;

	kvmi = kzalloc(sizeof(*kvmi), GFP_KERNEL);
	if (!kvmi)
		return NULL;

	kvmi->cmd_allow_mask = bitmap_zalloc(KVMI_NUM_COMMANDS, GFP_KERNEL);
	kvmi->event_allow_mask = bitmap_zalloc(KVMI_NUM_EVENTS, GFP_KERNEL);
	if (!kvmi->cmd_allow_mask || !kvmi->event_allow_mask) {
		bitmap_free(kvmi->cmd_allow_mask);
		bitmap_free(kvmi->event_allow_mask);
		kfree(kvmi);
		return NULL;
	}

	BUILD_BUG_ON(sizeof(hook->uuid) != sizeof(kvmi->uuid));
	memcpy(&kvmi->uuid, &hook->uuid, sizeof(kvmi->uuid));

	bitmap_copy(kvmi->cmd_allow_mask, Kvmi_always_allowed_commands,
		    KVMI_NUM_COMMANDS);

	atomic_set(&kvmi->ev_seq, 0);

	kvmi->kvm = kvm;

	return kvmi;
}

static void kvmi_destroy(struct kvm_introspection *kvmi)
{
	struct kvm *kvm = kvmi->kvm;

	kvmi_free(kvm);
}

static void kvmi_stop_recv_thread(struct kvm_introspection *kvmi)
{
	kvmi_sock_shutdown(kvmi);
}

static void __kvmi_unhook(struct kvm *kvm)
{
	struct kvm_introspection *kvmi = KVMI(kvm);

	wait_for_completion_killable(&kvm->kvmi_complete);
	kvmi_sock_put(kvmi);
}

static void kvmi_unhook(struct kvm *kvm)
{
	struct kvm_introspection *kvmi;

	mutex_lock(&kvm->kvmi_lock);

	kvmi = KVMI(kvm);
	if (kvmi) {
		kvmi_stop_recv_thread(kvmi);
		__kvmi_unhook(kvm);
		kvmi_destroy(kvmi);
	}

	mutex_unlock(&kvm->kvmi_lock);
}

int kvmi_ioctl_unhook(struct kvm *kvm)
{
	kvmi_unhook(kvm);
	return 0;
}

static void kvmi_put(struct kvm *kvm)
{
	if (refcount_dec_and_test(&kvm->kvmi_ref))
		complete(&kvm->kvmi_complete);
}

static int __kvmi_hook(struct kvm *kvm,
		       const struct kvm_introspection_hook *hook)
{
	struct kvm_introspection *kvmi = KVMI(kvm);

	if (!kvmi_sock_get(kvmi, hook->fd))
		return -EINVAL;

	return 0;
}

static int kvmi_recv_thread(void *arg)
{
	struct kvm_introspection *kvmi = arg;

	while (kvmi_msg_process(kvmi))
		;

	/* Signal userspace and prevent the vCPUs from sending events. */
	kvmi_sock_shutdown(kvmi);

	kvmi_put(kvmi->kvm);
	return 0;
}

static int kvmi_hook(struct kvm *kvm,
		     const struct kvm_introspection_hook *hook)
{
	struct kvm_introspection *kvmi;
	int err = 0;

	mutex_lock(&kvm->kvmi_lock);

	if (kvm->kvmi) {
		err = -EEXIST;
		goto out;
	}

	kvmi = kvmi_alloc(kvm, hook);
	if (!kvmi) {
		err = -ENOMEM;
		goto out;
	}

	kvm->kvmi = kvmi;

	err = __kvmi_hook(kvm, hook);
	if (err)
		goto destroy;

	init_completion(&kvm->kvmi_complete);

	refcount_set(&kvm->kvmi_ref, 1);

	kvmi->recv = kthread_run(kvmi_recv_thread, kvmi, "kvmi-recv");
	if (IS_ERR(kvmi->recv)) {
		err = -ENOMEM;
		kvmi_put(kvm);
		goto unhook;
	}

	goto out;

unhook:
	__kvmi_unhook(kvm);
destroy:
	kvmi_destroy(kvmi);
out:
	mutex_unlock(&kvm->kvmi_lock);
	return err;
}

int kvmi_ioctl_hook(struct kvm *kvm,
		    const struct kvm_introspection_hook *hook)
{
	if (hook->padding)
		return -EINVAL;

	return kvmi_hook(kvm, hook);
}

void kvmi_create_vm(struct kvm *kvm)
{
	mutex_init(&kvm->kvmi_lock);
}

void kvmi_destroy_vm(struct kvm *kvm)
{
	kvmi_unhook(kvm);
}

static int
kvmi_ioctl_get_feature(const struct kvm_introspection_feature *feat,
		       bool *allow, s32 *id, unsigned int nbits)
{
	s32 all_bits = -1;

	if (feat->id < 0 && feat->id != all_bits)
		return -EINVAL;

	if (feat->id > 0 && feat->id >= nbits)
		return -EINVAL;

	if (feat->allow > 1)
		return -EINVAL;

	*allow = feat->allow == 1;
	*id = feat->id;

	return 0;
}

static void kvmi_control_allowed_events(struct kvm_introspection *kvmi,
					s32 id, bool allow)
{
	s32 all_events = -1;

	if (allow) {
		if (id == all_events)
			bitmap_fill(kvmi->event_allow_mask, KVMI_NUM_EVENTS);
		else
			set_bit(id, kvmi->event_allow_mask);
	} else {
		if (id == all_events)
			bitmap_zero(kvmi->event_allow_mask, KVMI_NUM_EVENTS);
		else
			clear_bit(id, kvmi->event_allow_mask);
	}
}

int kvmi_ioctl_event(struct kvm *kvm,
		     const struct kvm_introspection_feature *feat)
{
	struct kvm_introspection *kvmi;
	bool allow;
	int err;
	s32 id;

	err = kvmi_ioctl_get_feature(feat, &allow, &id, KVMI_NUM_EVENTS);
	if (err)
		return err;

	mutex_lock(&kvm->kvmi_lock);

	kvmi = KVMI(kvm);
	if (kvmi)
		kvmi_control_allowed_events(kvmi, id, allow);
	else
		err = -EFAULT;

	mutex_unlock(&kvm->kvmi_lock);
	return err;
}

static int kvmi_control_allowed_commands(struct kvm_introspection *kvmi,
					 s32 id, bool allow)
{
	s32 all_commands = -1;

	if (allow) {
		if (id == all_commands)
			bitmap_fill(kvmi->cmd_allow_mask, KVMI_NUM_COMMANDS);
		else
			set_bit(id, kvmi->cmd_allow_mask);
	} else {
		if (id == all_commands)
			bitmap_copy(kvmi->cmd_allow_mask,
				    Kvmi_always_allowed_commands,
				    KVMI_NUM_COMMANDS);
		else if (test_bit(id, Kvmi_always_allowed_commands))
			return -EPERM;
		else
			clear_bit(id, kvmi->cmd_allow_mask);
	}

	return 0;
}

int kvmi_ioctl_command(struct kvm *kvm,
		       const struct kvm_introspection_feature *feat)
{
	struct kvm_introspection *kvmi;
	bool allow;
	int err;
	s32 id;

	err = kvmi_ioctl_get_feature(feat, &allow, &id, KVMI_NUM_COMMANDS);
	if (err)
		return err;

	mutex_lock(&kvm->kvmi_lock);

	kvmi = KVMI(kvm);
	if (kvmi)
		err = kvmi_control_allowed_commands(kvmi, id, allow);
	else
		err = -EFAULT;

	mutex_unlock(&kvm->kvmi_lock);
	return err;
}

static bool kvmi_unhook_event(struct kvm_introspection *kvmi)
{
	int err;

	err = kvmi_msg_send_unhook(kvmi);

	return !err;
}

int kvmi_ioctl_preunhook(struct kvm *kvm)
{
	struct kvm_introspection *kvmi;
	int err = 0;

	mutex_lock(&kvm->kvmi_lock);

	kvmi = KVMI(kvm);
	if (!kvmi) {
		err = -EFAULT;
		goto out;
	}

	if (!kvmi_unhook_event(kvmi))
		err = -ENOENT;

out:
	mutex_unlock(&kvm->kvmi_lock);
	return err;
}
