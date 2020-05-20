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
#include <linux/remote_mapping.h>

#include <uapi/linux/kvmi.h>
#include <trace/events/kvmi.h>

#include "kvmi_int.h"

#define KVMI_MEM_MAX_TOKENS 8
#define KVMI_MEM_TOKEN_TIMEOUT 3
#define TOKEN_TIMEOUT_NSEC (KVMI_MEM_TOKEN_TIMEOUT * NSEC_PER_SEC)

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
	struct kvm_introspection *kvmi;
	struct token_entry *tep;

	/* too many tokens have accumulated, retry later */
	kvmi = KVMI(kvm);
	if (atomic_read(&kvmi->num_tokens) > KVMI_MEM_MAX_TOKENS)
		return -KVM_EAGAIN;

	print_hex_dump_debug("kvmi: new token ", DUMP_PREFIX_NONE,
			     32, 1, token, sizeof(*token), false);

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
	tkn_gpa = kvm_mmu_gva_to_gpa_system(vcpu, tkn_gva, 0, NULL);
	if (tkn_gpa == UNMAPPED_GVA)
		return NULL;

	/* copy token to local address space */
	result = kvm_read_guest(vcpu->kvm, tkn_gpa, &token, sizeof(token));
	if (IS_ERR_VALUE(result)) {
		kvm_err("kvmi: failed copying token from user\n");
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

	return target_kvm;
}


int kvmi_host_mem_map(struct kvm_vcpu *vcpu, gva_t tkn_gva,
		      gpa_t req_gpa, gpa_t map_gpa)
{
	int result = 0;
	struct kvm *target_kvm;

	gfn_t req_gfn;
	hva_t req_hva;
	struct mm_struct *req_mm;

	gfn_t map_gfn;
	hva_t map_hva;

	kvm_debug("kvmi: mapping request req_gpa %016llx, map_gpa %016llx\n",
		  req_gpa, map_gpa);

	/* get the struct kvm * corresponding to the token */
	target_kvm = find_machine_at(vcpu, tkn_gva);
	if (IS_ERR_VALUE(target_kvm)) {
		return PTR_ERR(target_kvm);
	} else if (target_kvm == NULL) {
		kvm_err("kvmi: unable to find target machine\n");
		return -KVM_ENOENT;
	}
	req_mm = target_kvm->mm;

	trace_kvmi_mem_map(target_kvm, req_gpa, map_gpa);

	/* translate source addresses */
	req_gfn = gpa_to_gfn(req_gpa);
	req_hva = gfn_to_hva_safe(target_kvm, req_gfn);
	if (kvm_is_error_hva(req_hva)) {
		kvm_info("kvmi: invalid req_gpa %016llx\n", req_gpa);
		result = -KVM_EFAULT;
		goto out;
	}

	kvm_debug("kvmi: req_gpa %016llx -> req_hva %016lx\n",
		  req_gpa, req_hva);

	/* translate destination addresses */
	map_gfn = gpa_to_gfn(map_gpa);
	map_hva = gfn_to_hva_safe(vcpu->kvm, map_gfn);
	if (kvm_is_error_hva(map_hva)) {
		kvm_info("kvmi: invalid map_gpa %016llx\n", map_gpa);
		result = -KVM_EFAULT;
		goto out;
	}

	kvm_debug("kvmi: map_gpa %016llx -> map_hva %016lx\n",
		map_gpa, map_hva);

	/* actually do the mapping */
	result = mm_remote_map(req_mm, req_hva, map_hva);
	if (IS_ERR_VALUE((long)result)) {
		kvm_info("kvmi: mapping of req_gpa %016llx failed: %d.\n",
			req_gpa, result);
		goto out;
	}

	/* all fine */
	kvm_debug("kvmi: mapping of req_gpa %016llx successful\n", req_gpa);

out:
	kvm_put_kvm(target_kvm);

	return result;
}

int kvmi_host_mem_unmap(struct kvm_vcpu *vcpu, gpa_t map_gpa)
{
	gfn_t map_gfn;
	hva_t map_hva;
	int result;

	kvm_debug("kvmi: unmapping request for map_gpa %016llx\n", map_gpa);

	trace_kvmi_mem_unmap(map_gpa);

	/* convert GPA -> HVA */
	map_gfn = gpa_to_gfn(map_gpa);
	map_hva = gfn_to_hva_safe(vcpu->kvm, map_gfn);
	if (kvm_is_error_hva(map_hva)) {
		result = -KVM_EFAULT;
		kvm_info("kvmi: invalid map_gpa %016llx\n", map_gpa);
		goto out;
	}

	kvm_debug("kvmi: map_gpa %016llx -> map_hva %016lx\n",
		map_gpa, map_hva);

	/* actually do the unmapping */
	result = mm_remote_unmap(map_hva);
	if (IS_ERR_VALUE((long)result))
		goto out;

	kvm_debug("kvmi: unmapping of map_gpa %016llx successful\n", map_gpa);

out:
	return result;
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
