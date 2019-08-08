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

static struct kmem_cache *msg_cache;
static struct kmem_cache *job_cache;

static void kvmi_abort_events(struct kvm *kvm);

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
	kmem_cache_destroy(job_cache);
	job_cache = NULL;
}

static int kvmi_cache_create(void)
{
	job_cache = kmem_cache_create("kvmi_job",
				      sizeof(struct kvmi_job),
				      0, SLAB_ACCOUNT, NULL);
	msg_cache = kmem_cache_create("kvmi_msg", KVMI_MSG_SIZE_ALLOC,
				      4096, SLAB_ACCOUNT, NULL);

	if (!msg_cache || !job_cache) {
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

static bool alloc_kvmi(struct kvm *kvm, const struct kvm_introspection *qemu)
{
	struct kvmi *ikvm;

	ikvm = kzalloc(sizeof(*ikvm), GFP_KERNEL);
	if (!ikvm)
		return false;

	set_bit(KVMI_GET_VERSION, ikvm->cmd_allow_mask);
	set_bit(KVMI_CHECK_COMMAND, ikvm->cmd_allow_mask);
	set_bit(KVMI_CHECK_EVENT, ikvm->cmd_allow_mask);

	memcpy(&ikvm->uuid, &qemu->uuid, sizeof(ikvm->uuid));

	ikvm->kvm = kvm;
	kvm->kvmi = ikvm;

	return true;
}

static int __kvmi_add_job(struct kvm_vcpu *vcpu,
			  void (*fct)(struct kvm_vcpu *vcpu, void *ctx),
			  void *ctx, void (*free_fct)(void *ctx))
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvmi_job *job;

	job = kmem_cache_zalloc(job_cache, GFP_KERNEL);
	if (unlikely(!job))
		return -ENOMEM;

	INIT_LIST_HEAD(&job->link);
	job->fct = fct;
	job->ctx = ctx;
	job->free_fct = free_fct;

	spin_lock(&ivcpu->job_lock);
	list_add_tail(&job->link, &ivcpu->job_list);
	spin_unlock(&ivcpu->job_lock);

	return 0;
}

int kvmi_add_job(struct kvm_vcpu *vcpu,
		 void (*fct)(struct kvm_vcpu *vcpu, void *ctx),
		 void *ctx, void (*free_fct)(void *ctx))
{
	int err;

	err = __kvmi_add_job(vcpu, fct, ctx, free_fct);

	if (!err) {
		kvm_make_request(KVM_REQ_INTROSPECTION, vcpu);
		kvm_vcpu_kick(vcpu);
	}

	return err;
}

static void kvmi_free_job(struct kvmi_job *job)
{
	if (job->free_fct)
		job->free_fct(job->ctx);

	kmem_cache_free(job_cache, job);
}

static struct kvmi_job *kvmi_pull_job(struct kvmi_vcpu *ivcpu)
{
	struct kvmi_job *job = NULL;

	spin_lock(&ivcpu->job_lock);
	job = list_first_entry_or_null(&ivcpu->job_list, typeof(*job), link);
	if (job)
		list_del(&job->link);
	spin_unlock(&ivcpu->job_lock);

	return job;
}

static bool alloc_ivcpu(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu;

	ivcpu = kzalloc(sizeof(*ivcpu), GFP_KERNEL);
	if (!ivcpu)
		return false;

	INIT_LIST_HEAD(&ivcpu->job_list);
	spin_lock_init(&ivcpu->job_lock);

	vcpu->kvmi = ivcpu;

	return true;
}

struct kvmi * __must_check kvmi_get(struct kvm *kvm)
{
	if (refcount_inc_not_zero(&kvm->kvmi_ref))
		return kvm->kvmi;

	return NULL;
}

static void kvmi_clear_vcpu_jobs(struct kvm *kvm)
{
	int i;
	struct kvm_vcpu *vcpu;
	struct kvmi_job *cur, *next;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

		if (!ivcpu)
			continue;

		spin_lock(&ivcpu->job_lock);
		list_for_each_entry_safe(cur, next, &ivcpu->job_list, link) {
			list_del(&cur->link);
			kvmi_free_job(cur);
		}
		spin_unlock(&ivcpu->job_lock);
	}
}

static void kvmi_destroy(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	int i;

	kfree(kvm->kvmi);
	kvm->kvmi = NULL;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		kfree(vcpu->kvmi);
		vcpu->kvmi = NULL;
	}
}

static void kvmi_release(struct kvm *kvm)
{
	kvmi_sock_put(IKVM(kvm));
	kvmi_clear_vcpu_jobs(kvm);
	kvmi_destroy(kvm);

	complete(&kvm->kvmi_completed);
}

/* This function may be called from atomic context and must not sleep */
void kvmi_put(struct kvm *kvm)
{
	if (refcount_dec_and_test(&kvm->kvmi_ref))
		kvmi_release(kvm);
}

/*
 * VCPU hotplug - this function will likely be called before VCPU will start
 * executing code
 */
int kvmi_vcpu_init(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm;
	int ret = 0;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return 0;

	if (!alloc_ivcpu(vcpu)) {
		kvmi_err(ikvm, "Unable to alloc ivcpu for vcpu_id %u\n",
			 vcpu->vcpu_id);
		ret = -ENOMEM;
		goto out;
	}

out:
	kvmi_put(vcpu->kvm);

	return ret;
}

/*
 * VCPU hotplug - this function will likely be called after VCPU will stop
 * executing code
 */
void kvmi_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	/*
	 * Under certain circumstances (errors in creating the VCPU, hotplug?)
	 * this function may be reached with the KVMI member still allocated.
	 * This VCPU won't be reachable by the introspection engine, so no
	 * protection is necessary when de-allocating.
	 */
	kfree(vcpu->kvmi);
	vcpu->kvmi = NULL;
}

static void kvmi_end_introspection(struct kvmi *ikvm)
{
	struct kvm *kvm = ikvm->kvm;

	/* Signal QEMU which is waiting for POLLHUP. */
	kvmi_sock_shutdown(ikvm);

	/*
	 * Trigger all the VCPUs out of waiting for replies. Although the
	 * introspection is still enabled, sending additional events will
	 * fail because the socket is shut down. Waiting will not be possible.
	 */
	kvmi_abort_events(kvm);

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
	struct kvm_vcpu *vcpu;
	struct kvmi *ikvm;
	int i, err = 0;

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

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (!alloc_ivcpu(vcpu)) {
			err = -ENOMEM;
			goto err_alloc;
		}
	}

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
	unsigned long *dest;
	struct kvmi *ikvm;

	if (bitmap_empty(requested, nbits))
		return -EINVAL;

	ikvm = kvmi_get(kvm);
	if (!ikvm)
		return -EFAULT;

	dest = (unsigned long *)((char *)ikvm + off_dest);

	if (allow)
		bitmap_or(dest, dest, requested, nbits);
	else
		bitmap_andnot(dest, dest, requested, nbits);

	kvmi_put(kvm);

	return 0;
}

int kvmi_ioctl_event(struct kvm *kvm, void __user *argp)
{
	DECLARE_BITMAP(requested, KVMI_NUM_EVENTS);
	DECLARE_BITMAP(known, KVMI_NUM_EVENTS);
	bool allow;
	int err;
	int id;

	err = kvmi_ioctl_get_feature(argp, &allow, &id, requested);
	if (err)
		return err;

	bitmap_from_u64(known, KVMI_KNOWN_EVENTS);
	bitmap_and(requested, requested, known, KVMI_NUM_EVENTS);

	return kvmi_ioctl_feature(kvm, allow, requested,
				  offsetof(struct kvmi, event_allow_mask),
				  KVMI_NUM_EVENTS);
}

int kvmi_ioctl_command(struct kvm *kvm, void __user *argp)
{
	DECLARE_BITMAP(requested, KVMI_NUM_COMMANDS);
	DECLARE_BITMAP(known, KVMI_NUM_COMMANDS);
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
				|| id == KVMI_CHECK_COMMAND
				|| id == KVMI_CHECK_EVENT)
			return -EPERM;

		set_bit(KVMI_GET_VERSION, always_allowed);
		set_bit(KVMI_CHECK_COMMAND, always_allowed);
		set_bit(KVMI_CHECK_EVENT, always_allowed);

		bitmap_andnot(requested, requested, always_allowed,
			      KVMI_NUM_COMMANDS);
	}

	return kvmi_ioctl_feature(kvm, allow, requested,
				  offsetof(struct kvmi, cmd_allow_mask),
				  KVMI_NUM_COMMANDS);
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

void kvmi_run_jobs(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	struct kvmi_job *job;

	while ((job = kvmi_pull_job(ivcpu))) {
		job->fct(vcpu, job->ctx);
		kvmi_free_job(job);
	}
}

static bool done_waiting(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);

	return !list_empty(&ivcpu->job_list);
}

static void kvmi_job_wait(struct kvm_vcpu *vcpu, void *ctx)
{
	struct swait_queue_head *wq = kvm_arch_vcpu_wq(vcpu);
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	int err;

	err = swait_event_killable(*wq, done_waiting(vcpu));

	if (err)
		ivcpu->killed = true;
}

int kvmi_run_jobs_and_wait(struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu *ivcpu = IVCPU(vcpu);
	int err = 0;

	for (;;) {
		kvmi_run_jobs(vcpu);

		if (ivcpu->killed) {
			err = -1;
			break;
		}

		kvmi_add_job(vcpu, kvmi_job_wait, NULL, NULL);
	}

	return err;
}

void kvmi_handle_requests(struct kvm_vcpu *vcpu)
{
	struct kvmi *ikvm;

	ikvm = kvmi_get(vcpu->kvm);
	if (!ikvm)
		return;

	for (;;) {
		int err = kvmi_run_jobs_and_wait(vcpu);

		if (err)
			break;
	}

	kvmi_put(vcpu->kvm);
}

int kvmi_cmd_control_vm_events(struct kvmi *ikvm, unsigned int event_id,
			       bool enable)
{
	if (enable)
		set_bit(event_id, ikvm->vm_ev_mask);
	else
		clear_bit(event_id, ikvm->vm_ev_mask);

	return 0;
}

static void kvmi_job_abort(struct kvm_vcpu *vcpu, void *ctx)
{
}

static void kvmi_abort_events(struct kvm *kvm)
{
	int i;
	struct kvm_vcpu *vcpu;

	kvm_for_each_vcpu(i, vcpu, kvm)
		kvmi_add_job(vcpu, kvmi_job_abort, NULL, NULL);
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
