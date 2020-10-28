// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection memory mapping implementation
 *
 * Copyright (C) 2017-2019 Bitdefender S.R.L.
 *
 * Author:
 *   Mircea Cirjaliu <mcirjaliu@bitdefender.com>
 */

#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/spinlock.h>
#include <linux/printk.h>
#include <linux/random.h>
#include <linux/kvmi.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#include <linux/workqueue.h>
#include <linux/uuid.h>

#include <uapi/linux/kvmi.h>
#include <trace/events/kvmi.h>

#include "kvmi_int.h"

#define KVMI_MEM_MAX_TOKENS 8
#define KVMI_MEM_TOKEN_TIMEOUT 3
#define TOKEN_TIMEOUT_NSEC (KVMI_MEM_TOKEN_TIMEOUT * NSEC_PER_SEC)

#define TOKEN_FMT "%016llx..."
#define TOKEN_ARG(_tkn) ((_tkn).token[0])

static struct list_head token_list;
static spinlock_t token_lock;
static struct hrtimer token_timer;
static struct work_struct token_work;

struct token_entry {
	struct list_head token_list;
	struct kvmi_map_mem_token token;
	struct kvm *kvm;
	ktime_t timestamp;
};

void kvmi_clear_vm_tokens(struct kvm *kvm)
{
	struct token_entry *cur, *next;
	struct kvm_introspection *kvmi = KVMI(kvm);
	struct list_head temp;

	INIT_LIST_HEAD(&temp);

	spin_lock(&token_lock);
	list_for_each_entry_safe(cur, next, &token_list, token_list) {
		if (cur->kvm == kvm) {
			atomic_dec(&kvmi->num_tokens);

			list_del(&cur->token_list);
			list_add(&cur->token_list, &temp);
		}
	}
	spin_unlock(&token_lock);

	/* freeing a KVM may sleep */
	list_for_each_entry_safe(cur, next, &temp, token_list) {
		kvm_put_kvm(cur->kvm);
		kfree(cur);
	}
}

static void token_timeout_work(struct work_struct *work)
{
	struct token_entry *cur, *next;
	ktime_t now = ktime_get();
	struct kvm_introspection *kvmi;
	struct list_head temp;

	INIT_LIST_HEAD(&temp);

	spin_lock(&token_lock);
	list_for_each_entry_safe(cur, next, &token_list, token_list)
		if (ktime_sub(now, cur->timestamp) > TOKEN_TIMEOUT_NSEC) {
			kvmi = kvmi_get(cur->kvm);
			if (kvmi) {
				atomic_dec(&kvmi->num_tokens);
				kvmi_put(cur->kvm);
			}

			list_del(&cur->token_list);
			list_add(&cur->token_list, &temp);
		}
	spin_unlock(&token_lock);

	if (!list_empty(&temp))
		kvm_info("kvmi: token(s) timed out\n");

	/* freeing a KVM may sleep */
	list_for_each_entry_safe(cur, next, &temp, token_list) {
		kvm_put_kvm(cur->kvm);
		kfree(cur);
	}
}

static enum hrtimer_restart token_timer_fn(struct hrtimer *timer)
{
	schedule_work(&token_work);

	hrtimer_add_expires_ns(timer, NSEC_PER_SEC);
	return HRTIMER_RESTART;
}

int kvmi_mem_generate_token(struct kvm *kvm, struct kvmi_map_mem_token *token)
{
	struct kvm_introspection *kvmi = KVMI(kvm);
	struct token_entry *tep;

	/* too many tokens have accumulated, retry later */
	if (atomic_read(&kvmi->num_tokens) > KVMI_MEM_MAX_TOKENS)
		return -KVM_EAGAIN;

	tep = kmalloc(sizeof(*tep), GFP_KERNEL);
	if (tep == NULL)
		return -KVM_ENOMEM;

	/* pin KVM so it won't go away while we wait for HC */
	kvm_get_kvm(kvm);
	get_random_bytes(token, sizeof(*token));
	atomic_inc(&kvmi->num_tokens);

	/* init token entry */
	INIT_LIST_HEAD(&tep->token_list);
	memcpy(&tep->token, token, sizeof(*token));
	tep->kvm = kvm;
	tep->timestamp = ktime_get();

	/* add to list */
	spin_lock(&token_lock);
	list_add_tail(&tep->token_list, &token_list);
	spin_unlock(&token_lock);

	kvm_debug("%s: kvm %lx -> token "TOKEN_FMT"\n",
		__func__, (long)kvm, TOKEN_ARG(*token));

	return 0;
}

static struct kvm *find_machine_at(struct kvm_vcpu *vcpu, gva_t tkn_gva)
{
	long result;
	gpa_t tkn_gpa;
	struct kvmi_map_mem_token token;
	struct list_head *cur;
	struct token_entry *tep, *found = NULL;
	struct kvm *target_kvm = NULL;
	struct kvm_introspection *kvmi;

	/* machine token is passed as pointer */
	tkn_gpa = kvm_mmu_gva_to_gpa_read(vcpu, tkn_gva, NULL);
	if (tkn_gpa == UNMAPPED_GVA)
		return NULL;

	/* copy token to local address space */
	result = kvm_read_guest(vcpu->kvm, tkn_gpa, &token, sizeof(token));
	if (IS_ERR_VALUE(result)) {
		kvmi_warn(vcpu->kvm->kvmi, "failed copying token from user\n");
		return ERR_PTR(result);
	}

	/* consume token & find the VM */
	spin_lock(&token_lock);
	list_for_each(cur, &token_list) {
		tep = list_entry(cur, struct token_entry, token_list);

		if (!memcmp(&token, &tep->token, sizeof(token))) {
			list_del(&tep->token_list);
			found = tep;
			break;
		}
	}
	spin_unlock(&token_lock);

	if (found != NULL) {
		target_kvm = found->kvm;
		kfree(found);

		kvmi = kvmi_get(target_kvm);
		if (kvmi) {
			atomic_dec(&kvmi->num_tokens);
			kvmi_put(target_kvm);
		}
	}

	//kvm_debug("%s: token "TOKEN_FMT" -> kvm %lx\n",
	//	__func__, TOKEN_ARG(token), (long)target_kvm);

	return target_kvm;
}

int kvmi_host_remote_start(struct kvm_vcpu *vcpu, gva_t id_gva)
{
	gpa_t gpa;
	uuid_t dom_id;
	int result = 0;

	kvm_debug("%s: vcpu %lx, handle %lx\n",
		__func__, (long)vcpu, (long)id_gva);

	/* extract the request from the local guest */
	gpa = kvm_mmu_gva_to_gpa_read(vcpu, id_gva, NULL);
	if (gpa == UNMAPPED_GVA)
		return -KVM_EINVAL;

	result = kvm_vcpu_read_guest(vcpu, gpa, &dom_id, sizeof(dom_id));
	if (result)
		return result;

	/* this will advance the state of the vcpu and return success anyway */
	kvmi_introspection_hc_end(vcpu, 0);

	/* exit to QEMU */
	vcpu->run->exit_reason = KVM_EXIT_INTROSPECTION;
	vcpu->run->kvmi.type = KVM_EXIT_INTROSPECTION_START;
	uuid_copy((uuid_t *)&vcpu->run->kvmi.kvmi_start.uuid, &dom_id);

	return 0;
}

int kvmi_host_remote_end(struct kvm_vcpu *vcpu, gva_t id_gva)
{
	gpa_t gpa;
	uuid_t dom_id;
	int result = 0;

	kvm_debug("%s: vcpu %lx, handle %lx\n",
		__func__, (long)vcpu, (long)id_gva);

	/* extract the request from the local guest */
	gpa = kvm_mmu_gva_to_gpa_read(vcpu, id_gva, NULL);
	if (gpa == UNMAPPED_GVA)
		return -KVM_EINVAL;

	result = kvm_vcpu_read_guest(vcpu, gpa, &dom_id, sizeof(dom_id));
	if (result)
		return result;

	/* this will advance the state of the vcpu and return success anyway */
	kvmi_introspection_hc_end(vcpu, 0);

	/* exit to QEMU */
	vcpu->run->exit_reason = KVM_EXIT_INTROSPECTION;
	vcpu->run->kvmi.type = KVM_EXIT_INTROSPECTION_END;
	uuid_copy((uuid_t *)&vcpu->run->kvmi.kvmi_start.uuid, &dom_id);

	return 0;
}

struct kvmi_mem_holder {
	gva_t handle;
	struct kvmi_mem_map mem_map;
};

static struct kvmi_mem_holder holders[KVM_MAX_VCPUS];

/* This thing only requests the mapping, does not return anything to the guest */
int kvmi_host_remote_map(struct kvm_vcpu *vcpu, gva_t tkn_gva, gva_t handle)
{
	struct kvmi_mem_holder *holder = &holders[vcpu->vcpu_id];
	gpa_t gpa;
	struct kvmi_mem_map request;
	struct kvm *target_kvm;
	struct kvm_memory_slot *memslot;
	int result = 0;
	int idx;

	//kvm_debug("%s: vcpu %lx, handle %lx\n",
	//	__func__, (long)vcpu, (long)handle);

	/* extract the mapping request from the local guest */
	gpa = kvm_mmu_gva_to_gpa_read(vcpu, handle, NULL);
	if (gpa == UNMAPPED_GVA)
		return -KVM_EINVAL;

	/* read request content from guest */
	result = kvm_vcpu_read_guest(vcpu, gpa, &request, sizeof(request));
	if (result)
		return result;

	kvm_debug("%s: vcpu %lx, req_gpa %lx\n",
		__func__, (long)vcpu, (long)request.req_gpa);

	/* get the struct kvm * corresponding to the token */
	target_kvm = find_machine_at(vcpu, tkn_gva);
	if (IS_ERR_VALUE(target_kvm)) {
		return PTR_ERR(target_kvm);
	} else if (!target_kvm) {
		kvmi_warn(vcpu->kvm->kvmi, "unable to find target machine\n");
		return -KVM_ENOENT;
	}

	/* get info about the memslot containing req_gpa */
	idx = srcu_read_lock(&target_kvm->srcu);
	memslot = gfn_to_memslot(target_kvm, gpa_to_gfn(request.req_gpa));
	if (!memslot) {
		result = -KVM_EINVAL;
		goto out;
	}

	kvm_debug("%s: memslot offset %llx, hva %lx, len %lx\n", __func__,
		gfn_to_gpa(memslot->base_gfn), memslot->userspace_addr,
		memslot->npages * PAGE_SIZE);

	/* store data until ioctl() from QEMU arrives */
	holder->handle = handle;
	request.req_start = memslot->base_gfn << PAGE_SHIFT;
	request.req_length = memslot->npages * PAGE_SIZE;
	memcpy(&holder->mem_map, &request, sizeof(struct kvmi_mem_map));

	/* request mapping from QEMU */
	vcpu->run->exit_reason = KVM_EXIT_INTROSPECTION;
	vcpu->run->kvmi.type = KVM_EXIT_INTROSPECTION_MAP;
	uuid_copy((uuid_t *)&vcpu->run->kvmi.kvmi_map.uuid, &request.dom_id);
	vcpu->run->kvmi.kvmi_map.gpa = memslot->base_gfn << PAGE_SHIFT;
	vcpu->run->kvmi.kvmi_map.len = memslot->npages * PAGE_SIZE;
	vcpu->run->kvmi.kvmi_map.min = request.min_map;

out:
	srcu_read_unlock(&target_kvm->srcu, idx);
	kvm_put_kvm(target_kvm);

	/* predict failure in case QEMU does not call the following IOCTL */
	if (result == 0)
		kvmi_introspection_hc_end(vcpu, -KVM_EFAULT);

	return result;
}

/*
 * IOCTL from QEMU that finishes the hypercall started above.
 * Communicates to guest the GPA where mapping has been done.
 * Also returns the error value to QEMU.
 */
int kvmi_vcpu_ioctl_map(struct kvm_vcpu *vcpu, u64 arg)
{
	struct kvmi_mem_holder *holder = &holders[vcpu->vcpu_id];
	struct kvmi_mem_map *request = &holder->mem_map;
	gpa_t gpa;
	int result = -1;	/* this goes to guest */
	int idx;

	kvm_debug("%s: address %lx\n", __func__, (long)arg);

	vcpu_load(vcpu);

	/* QEMU failed to do memory mapping */
	if (IS_ERR_VALUE(arg)) {
		result = (int) arg;
		goto out;
	}

	/* complete the request & pass to guest */
	request->map_start = arg;

	/* this acts on the local vcpu/kvm, but from a QEMU call */
	/* still gotta protect against memslot modification */
	idx = srcu_read_lock(&vcpu->kvm->srcu);

	gpa = kvm_mmu_gva_to_gpa_write(vcpu, holder->handle, NULL);
	if (gpa == UNMAPPED_GVA)
		goto out_srcu;

	result = kvm_vcpu_write_guest(vcpu, gpa, request, sizeof(*request));

	/*
	 * if writing to guest fails, the guest won't know about the
	 * range being hotplugged, so QEMU will have to drop it;
	 * return result also to QEMU
	 */

out_srcu:
	srcu_read_unlock(&vcpu->kvm->srcu, idx);
out:
	/* overwrite the return-from-hypercall value for guest */
	kvmi_introspection_hc_return(vcpu, result);

	vcpu_put(vcpu);

	return result;		/* this goes back to QEMU */
}

int kvmi_host_remote_unmap(struct kvm_vcpu *vcpu, gva_t handle)
{
	gpa_t gpa;
	struct kvmi_mem_unmap request;
	int result = 0;

	//kvm_debug("%s: vcpu %lx, handle %lx\n",
	//	__func__, (long)vcpu, (long)handle);

	/* extract the mapping request from the local guest */
	gpa = kvm_mmu_gva_to_gpa_read(vcpu, handle, NULL);
	if (gpa == UNMAPPED_GVA)
		return -KVM_EINVAL;

	/* read request content from guest */
	result = kvm_vcpu_read_guest(vcpu, gpa, &request, sizeof(request));
	if (result)
		return result;

	kvm_debug("%s: vcpu %lx, map_gpa %lx\n",
		__func__, (long)vcpu, (long)request.map_gpa);

	/* this will advance the state of the vcpu and return success anyway */
	kvmi_introspection_hc_end(vcpu, 0);

	/* request unmapping from QEMU */
	vcpu->run->exit_reason = KVM_EXIT_INTROSPECTION;
	vcpu->run->kvmi.type = KVM_EXIT_INTROSPECTION_UNMAP;
	uuid_copy((uuid_t *)&vcpu->run->kvmi.kvmi_unmap.uuid, &request.dom_id);
	vcpu->run->kvmi.kvmi_unmap.gpa = request.map_gpa;

	return 0;
}

void kvmi_mem_init(void)
{
	ktime_t expire;

	INIT_LIST_HEAD(&token_list);
	spin_lock_init(&token_lock);
	INIT_WORK(&token_work, token_timeout_work);

	hrtimer_init(&token_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	token_timer.function = token_timer_fn;
	expire = ktime_add_ns(ktime_get(), NSEC_PER_SEC);
	hrtimer_start(&token_timer, expire, HRTIMER_MODE_ABS);

	kvm_info("kvmi: initialized host memory introspection\n");
}

void kvmi_mem_exit(void)
{
	hrtimer_cancel(&token_timer);
}
