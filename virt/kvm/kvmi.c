// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection
 *
 * Copyright (C) 2017-2019 Bitdefender S.R.L.
 *
 */
#include <uapi/linux/kvmi.h>
#include "kvmi_int.h"

int kvmi_init(void)
{
	return 0;
}

void kvmi_uninit(void)
{
}

struct kvmi * __must_check kvmi_get(struct kvm *kvm)
{
	if (refcount_inc_not_zero(&kvm->kvmi_ref))
		return kvm->kvmi;

	return NULL;
}

static void kvmi_destroy(struct kvm *kvm)
{
}

static void kvmi_release(struct kvm *kvm)
{
	kvmi_destroy(kvm);

	complete(&kvm->kvmi_completed);
}

/* This function may be called from atomic context and must not sleep */
void kvmi_put(struct kvm *kvm)
{
	if (refcount_dec_and_test(&kvm->kvmi_ref))
		kvmi_release(kvm);
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

	kvmi_put(kvm);

	/* wait for introspection resources to be released */
	wait_for_completion_killable(&kvm->kvmi_completed);
}
