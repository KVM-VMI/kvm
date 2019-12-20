// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection
 *
 * Copyright (C) 2017-2020 Bitdefender S.R.L.
 *
 */
#include "kvmi_int.h"
#include <linux/kthread.h>

static struct kmem_cache *msg_cache;

void *kvmi_msg_alloc(void)
{
	return kmem_cache_zalloc(msg_cache, GFP_KERNEL);
}

void *kvmi_msg_alloc_check(size_t size)
{
	if (size > KVMI_MSG_SIZE_ALLOC)
		return NULL;
	return kvmi_msg_alloc();
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

int kvmi_init(void)
{
	return kvmi_cache_create();
}

void kvmi_uninit(void)
{
	kvmi_cache_destroy();
}

static void free_kvmi(struct kvm *kvm)
{
	kfree(kvm->kvmi);
	kvm->kvmi = NULL;
}

static struct kvm_introspection *
alloc_kvmi(struct kvm *kvm, const struct kvm_introspection_hook *hook)
{
	struct kvm_introspection *kvmi;

	kvmi = kzalloc(sizeof(*kvmi), GFP_KERNEL);
	if (!kvmi)
		return NULL;

	BUILD_BUG_ON(sizeof(hook->uuid) != sizeof(kvmi->uuid));
	memcpy(&kvmi->uuid, &hook->uuid, sizeof(kvmi->uuid));

	set_bit(KVMI_GET_VERSION, kvmi->cmd_allow_mask);
	set_bit(KVMI_VM_CHECK_COMMAND, kvmi->cmd_allow_mask);
	set_bit(KVMI_VM_CHECK_EVENT, kvmi->cmd_allow_mask);

	kvmi->kvm = kvm;

	return kvmi;
}

static void kvmi_destroy(struct kvm_introspection *kvmi)
{
	struct kvm *kvm = kvmi->kvm;

	free_kvmi(kvm);
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

struct kvm_introspection * __must_check kvmi_get(struct kvm *kvm)
{
	if (refcount_inc_not_zero(&kvm->kvmi_ref))
		return kvm->kvmi;

	return NULL;
}

void kvmi_put(struct kvm *kvm)
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

	/*
	 * Signal userspace (which might wait for POLLHUP only)
	 * and prevent the vCPUs from sending other events.
	 */
	kvmi_sock_shutdown(kvmi);

	kvmi_put(kvmi->kvm);
	return 0;
}

int kvmi_hook(struct kvm *kvm, const struct kvm_introspection_hook *hook)
{
	struct kvm_introspection *kvmi;
	int err = 0;

	mutex_lock(&kvm->kvmi_lock);

	if (kvm->kvmi) {
		err = -EEXIST;
		goto out;
	}

	kvmi = alloc_kvmi(kvm, hook);
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
	/*
	 * Paired with refcount_inc_not_zero() from kvmi_get().
	 */
	smp_wmb();

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

int kvmi_ioctl_hook(struct kvm *kvm, void __user *argp)
{
	struct kvm_introspection_hook i;

	if (copy_from_user(&i, argp, sizeof(i)))
		return -EFAULT;

	if (i.padding)
		return -EINVAL;

	return kvmi_hook(kvm, &i);
}

void kvmi_create_vm(struct kvm *kvm)
{
	mutex_init(&kvm->kvmi_lock);
}

void kvmi_destroy_vm(struct kvm *kvm)
{
	kvmi_unhook(kvm);
}

static int kvmi_ioctl_get_feature(void __user *argp, bool *allow, int *id,
				  unsigned long *bitmask)
{
	struct kvm_introspection_feature feat;
	int all_bits = -1;

	if (copy_from_user(&feat, argp, sizeof(feat)))
		return -EFAULT;

	if (feat.id < 0 && feat.id != all_bits)
		return -EINVAL;

	*allow = !!(feat.allow & 1);
	*id = feat.id;
	*bitmask = *id == all_bits ? -1 : BIT(feat.id);

	return 0;
}

static int kvmi_ioctl_feature(struct kvm *kvm,
			      bool allow, unsigned long *requested,
			      size_t off_dest, unsigned int nbits)
{
	struct kvm_introspection *kvmi;
	unsigned long *dest;
	int err = 0;

	mutex_lock(&kvm->kvmi_lock);

	kvmi = KVMI(kvm);
	if (!kvmi) {
		err = -EFAULT;
		goto out;
	}

	dest = (unsigned long *)((char *)kvmi + off_dest);

	if (allow)
		bitmap_or(dest, dest, requested, nbits);
	else
		bitmap_andnot(dest, dest, requested, nbits);

out:
	mutex_unlock(&kvm->kvmi_lock);

	return err;
}

int kvmi_ioctl_event(struct kvm *kvm, void __user *argp)
{
	DECLARE_BITMAP(requested, KVMI_NUM_EVENTS);
	DECLARE_BITMAP(known, KVMI_NUM_EVENTS);
	size_t off_bitmap;
	bool allow;
	int err;
	int id;

	err = kvmi_ioctl_get_feature(argp, &allow, &id, requested);
	if (err)
		return err;

	bitmap_from_u64(known, KVMI_KNOWN_EVENTS);
	bitmap_and(requested, requested, known, KVMI_NUM_EVENTS);

	off_bitmap = offsetof(struct kvm_introspection, event_allow_mask);

	return kvmi_ioctl_feature(kvm, allow, requested, off_bitmap,
				  KVMI_NUM_EVENTS);
}

int kvmi_ioctl_command(struct kvm *kvm, void __user *argp)
{
	DECLARE_BITMAP(requested, KVMI_NUM_COMMANDS);
	DECLARE_BITMAP(known, KVMI_NUM_COMMANDS);
	size_t off_bitmap;
	bool allow;
	int err;
	int id;

	err = kvmi_ioctl_get_feature(argp, &allow, &id, requested);
	if (err)
		return err;

	bitmap_from_u64(known, KVMI_KNOWN_COMMANDS);
	bitmap_and(requested, requested, known, KVMI_NUM_COMMANDS);

	if (!allow) {
		DECLARE_BITMAP(always_allowed, KVMI_NUM_COMMANDS);

		if (id == KVMI_GET_VERSION
				|| id == KVMI_VM_CHECK_COMMAND
				|| id == KVMI_VM_CHECK_EVENT)
			return -EPERM;

		set_bit(KVMI_GET_VERSION, always_allowed);
		set_bit(KVMI_VM_CHECK_COMMAND, always_allowed);
		set_bit(KVMI_VM_CHECK_EVENT, always_allowed);

		bitmap_andnot(requested, requested, always_allowed,
			      KVMI_NUM_COMMANDS);
	}

	off_bitmap = offsetof(struct kvm_introspection, cmd_allow_mask);

	return kvmi_ioctl_feature(kvm, allow, requested, off_bitmap,
				  KVMI_NUM_COMMANDS);
}
