// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection
 *
 * Copyright (C) 2017-2019 Bitdefender S.R.L.
 *
 */
#include <uapi/linux/kvmi.h>
#include "kvmi_int.h"
#include <linux/kthread.h>
#include <linux/bitmap.h>

int kvmi_init(void)
{
	return 0;
}

void kvmi_uninit(void)
{
}

static bool alloc_kvmi(struct kvm *kvm, const struct kvm_introspection *qemu)
{
	struct kvmi *ikvm;

	ikvm = kzalloc(sizeof(*ikvm), GFP_KERNEL);
	if (!ikvm)
		return false;

	memcpy(&ikvm->uuid, &qemu->uuid, sizeof(ikvm->uuid));

	ikvm->kvm = kvm;
	kvm->kvmi = ikvm;

	return true;
}

struct kvmi * __must_check kvmi_get(struct kvm *kvm)
{
	if (refcount_inc_not_zero(&kvm->kvmi_ref))
		return kvm->kvmi;

	return NULL;
}

static void kvmi_destroy(struct kvm *kvm)
{
	kfree(kvm->kvmi);
	kvm->kvmi = NULL;
}

static void kvmi_release(struct kvm *kvm)
{
	kvmi_sock_put(IKVM(kvm));
	kvmi_destroy(kvm);

	complete(&kvm->kvmi_completed);
}

/* This function may be called from atomic context and must not sleep */
void kvmi_put(struct kvm *kvm)
{
	if (refcount_dec_and_test(&kvm->kvmi_ref))
		kvmi_release(kvm);
}

static void kvmi_end_introspection(struct kvmi *ikvm)
{
	struct kvm *kvm = ikvm->kvm;

	/* Signal QEMU which is waiting for POLLHUP. */
	kvmi_sock_shutdown(ikvm);

	/*
	 * At this moment the socket is shut down, no more commands will come
	 * from the introspector, and the only way into the introspection is
	 * thru the event handlers. Make sure the introspection ends.
	 */
	kvmi_put(kvm);
}

static int kvmi_recv(void *arg)
{
	struct kvmi *ikvm = arg;

	kvmi_info(ikvm, "Hooking VM\n");

	while (kvmi_msg_process(ikvm))
		;

	kvmi_info(ikvm, "Unhooking VM\n");

	kvmi_end_introspection(ikvm);

	return 0;
}

int kvmi_hook(struct kvm *kvm, const struct kvm_introspection *qemu)
{
	struct kvmi *ikvm;
	int err = 0;

	/* wait for the previous introspection to finish */
	err = wait_for_completion_killable(&kvm->kvmi_completed);
	if (err)
		return err;

	/* ensure no VCPU hotplug happens until we set the reference */
	mutex_lock(&kvm->lock);

	if (!alloc_kvmi(kvm, qemu)) {
		mutex_unlock(&kvm->lock);
		return -ENOMEM;
	}
	ikvm = IKVM(kvm);

	/* interact with other kernel components after structure allocation */
	if (!kvmi_sock_get(ikvm, qemu->fd)) {
		err = -EINVAL;
		goto err_alloc;
	}

	/*
	 * Make sure all the KVM/KVMI structures are linked and no pointer
	 * is read as NULL after the reference count has been set.
	 */
	smp_mb__before_atomic();
	refcount_set(&kvm->kvmi_ref, 1);

	mutex_unlock(&kvm->lock);

	ikvm->recv = kthread_run(kvmi_recv, ikvm, "kvmi-recv");
	if (IS_ERR(ikvm->recv)) {
		kvmi_err(ikvm, "Unable to create receiver thread!\n");
		err = PTR_ERR(ikvm->recv);
		goto err_recv;
	}

	return 0;

err_recv:
	/*
	 * introspection has oficially started since reference count has been
	 * set (and some event handlers may have already acquired it), but
	 * without the receiver thread; we must emulate its shutdown behavior
	 */
	kvmi_end_introspection(ikvm);

	return err;

err_alloc:
	kvmi_release(kvm);

	mutex_unlock(&kvm->lock);

	return err;
}

int kvmi_ioctl_hook(struct kvm *kvm, void __user *argp)
{
	struct kvm_introspection i;

	if (copy_from_user(&i, argp, sizeof(i)))
		return -EFAULT;

	if (i.padding)
		return -EINVAL;

	return kvmi_hook(kvm, &i);
}

void kvmi_create_vm(struct kvm *kvm)
{
	init_completion(&kvm->kvmi_completed);
	complete(&kvm->kvmi_completed);
}

void kvmi_destroy_vm(struct kvm *kvm)
{
	struct kvmi *ikvm;

	ikvm = kvmi_get(kvm);
	if (!ikvm)
		return;

	/* trigger socket shutdown - kvmi_recv() will start shutdown process */
	kvmi_sock_shutdown(ikvm);

	kvmi_put(kvm);

	/* wait for introspection resources to be released */
	wait_for_completion_killable(&kvm->kvmi_completed);
}

int kvmi_ioctl_unhook(struct kvm *kvm, bool force_reset)
{
	struct kvmi *ikvm;
	int err = 0;

	ikvm = kvmi_get(kvm);
	if (!ikvm)
		return -EFAULT;

	kvm_info("TODO: %s force_reset %d", __func__, force_reset);

	kvmi_put(kvm);

	return err;
}
