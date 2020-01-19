// SPDX-License-Identifier: GPL-2.0
/*
 * Sub-Page Permission test
 *
 * Copyright (C) 2019, Intel Corp.
 *
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "../../lib/kvm_util_internal.h"
#include "linux/kvm.h"

#define VCPU_ID           1
#define PAGE_SIZE         (4096)
#define SPP_GUARD_SIZE    (16 * PAGE_SIZE)
#define SPP_GUARD_MEMSLOT (1)
#define SPP_GUARD_PAGES   (SPP_GUARD_SIZE / PAGE_SIZE)
#define SPP_GUARD_GPA      0x10000000

#define SUBPAGE_ACCESS_DEFAULT   (0x0)
#define SUBPAGE_ACCESS_FULL      (0xFFFFFFFF)
#define START_SPP_VM_ADDR        (0x700000)
#define SUBPAGE_SIZE             (128)

vm_vaddr_t vspp_start;
vm_paddr_t pspp_start;

void guest_code(void)
{
	uint8_t *iterator = (uint8_t *)vspp_start;
	int count;

	GUEST_SYNC(1);
	/*
	 * expect EPT violation induced by SPP in each interation since
	 * the full page is protected by SPP.
	 */
	for (count = 0; count < PAGE_SIZE / SUBPAGE_SIZE; count++) {
		*(uint32_t *)(iterator) = 0x99;
		iterator += SUBPAGE_SIZE;
	}
	GUEST_SYNC(2);
	iterator = (uint8_t *)vspp_start;

	/*
	 * don't expect EPT violation happen since SPP is disabled
	 * for the page
	 */
	for (count = 0; count < PAGE_SIZE / SUBPAGE_SIZE; count++) {
		*(uint32_t *)(iterator) = 0x99;
		iterator += SUBPAGE_SIZE;
	}
}

void prepare_test(struct kvm_vm **g_vm, struct kvm_run **g_run)
{
	void *spp_hva;
	struct kvm_vm *vm;
	struct kvm_run *run;
	/* Create VM, SPP is only valid for 4KB page mode */
	*g_vm = vm_create_default(VCPU_ID, 0, guest_code);
	vm = *g_vm;

	*g_run = vcpu_state(vm, VCPU_ID);
	run = *g_run;

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, SPP_GUARD_GPA,
				    SPP_GUARD_MEMSLOT, SPP_GUARD_PAGES, 0);

	pspp_start = vm_phy_pages_alloc(vm, 1, SPP_GUARD_GPA,
					SPP_GUARD_MEMSLOT);

	memset(addr_gpa2hva(vm, SPP_GUARD_GPA), 0x0, PAGE_SIZE);

	virt_map(vm, START_SPP_VM_ADDR, SPP_GUARD_GPA, PAGE_SIZE, 0);

	vspp_start = vm_vaddr_alloc(vm, PAGE_SIZE, START_SPP_VM_ADDR,
				    SPP_GUARD_MEMSLOT, 0);

	spp_hva = addr_gva2hva(vm, vspp_start);

	pspp_start = addr_hva2gpa(vm, spp_hva);

	printf("SPP protected zone: size = %d, gva = 0x%lx, gpa = 0x%lx, "
	       "hva = 0x%p\n", PAGE_SIZE, vspp_start, pspp_start, spp_hva);

	/* make sure the virtual address is visible to VM. */
	sync_global_to_guest(vm, vspp_start);

	vcpu_run(vm, VCPU_ID);

	TEST_ASSERT(run->exit_reason == KVM_EXIT_IO,
		    "exit reason: %u (%s),\n", run->exit_reason,
		     exit_reason_str(run->exit_reason));
}

void setup_spp(struct kvm_vm *vm)
{
	struct kvm_enable_cap cap;
	int ret = 0;
	struct kvm_subpage *sp;
	int len;

	memset(&cap, 0, sizeof(cap));
	cap.cap = KVM_CAP_X86_SPP;
	cap.flags = 0;

	/* initialize the SPP runtime environment.*/
	ret = ioctl(vm->fd, KVM_ENABLE_CAP, &cap);
	TEST_ASSERT(ret == 0, "KVM_CAP_X86_SPP failed.");
	len = sizeof(*sp) + sizeof(__u32);
	printf("SPP initialized successfully.\n");

	sp = malloc(len);
	TEST_ASSERT(sp > 0, "Low memory 1!");
	memset(sp, 0, len);
	/* set up SPP protection for the page. */
	sp->npages = 1;
	sp->gfn_base = pspp_start >> 12;
	sp->access_map[0] = SUBPAGE_ACCESS_DEFAULT;
	ret = ioctl(vm->fd, KVM_SUBPAGES_SET_ACCESS, sp);

	TEST_ASSERT(ret == 1, "KVM_SUBPAGES_SET_ACCESS failed. ret = 0x%x, "
		    "gfn_base = 0x%llx\n", ret, sp->gfn_base);
	printf("set spp protection info: gfn = 0x%llx, access = 0x%x, "
	       "npages = %d\n", sp->gfn_base, sp->access_map[0],
	       sp->npages);

	memset(sp, 0, len);
	/* make sure the SPP permission bits are actully set as expected. */
	sp->npages = 1;
	sp->gfn_base = pspp_start >> 12;

	ret = ioctl(vm->fd, KVM_SUBPAGES_GET_ACCESS, sp);

	TEST_ASSERT(ret == 1, "KVM_SUBPAGES_GET_ACCESS failed.");

	TEST_ASSERT(sp->access_map[0] == SUBPAGE_ACCESS_DEFAULT,
		    "subpage access didn't match.");
	printf("get spp protection info: gfn = 0x%llx, access = 0x%x, "
	       "npages = %d\n", sp->gfn_base,
	       sp->access_map[0], sp->npages);

	free(sp);
	printf("got matched subpage permission vector.\n");
	printf("expect VM exits caused by SPP below.\n");
}

void unset_spp(struct kvm_vm *vm)
{
	struct kvm_subpage *sp;
	int len;

	len = sizeof(*sp) + sizeof(__u32);
	sp = malloc(len);
	TEST_ASSERT(sp > 0, "Low memory 2!");
	memset(sp, 0, len);

	/* now unprotect the SPP to the page.*/
	sp->npages = 1;
	sp->gfn_base = pspp_start >> 12;
	sp->access_map[0] = SUBPAGE_ACCESS_FULL;
	ioctl(vm->fd, KVM_SUBPAGES_SET_ACCESS, sp);

	printf("unset SPP protection at gfn: 0x%llx\n", sp->gfn_base);
	printf("expect NO VM exits caused by SPP below.\n");
	free(sp);
}

#define TEST_SYNC_FIELDS   KVM_SYNC_X86_REGS

void run_test(struct kvm_vm *vm, struct kvm_run *run)
{
	int loop;
	int ept_fault = 0;
	struct kvm_regs regs;

	run->kvm_valid_regs = TEST_SYNC_FIELDS;
	vcpu_run(vm, VCPU_ID);

	for (loop = 0; loop < PAGE_SIZE / SUBPAGE_SIZE; loop++) {
		/*
		 * if everything goes correctly, should get VM exit
		 * with KVM_EXIT_SPP.
		 */
		TEST_ASSERT(run->exit_reason == KVM_EXIT_SPP,
			    "exit reason: %u (%s),\n", run->exit_reason,
			    exit_reason_str(run->exit_reason));
		printf("%d - exit reason: %s\n", loop + 1,
		       exit_reason_str(run->exit_reason));
		ept_fault++;

		vcpu_regs_get(vm, VCPU_ID, &regs);

		run->s.regs.regs.rip += run->spp.insn_len;

		run->kvm_valid_regs = TEST_SYNC_FIELDS;
		run->kvm_dirty_regs = KVM_SYNC_X86_REGS;

		vcpu_run(vm, VCPU_ID);
	}

	printf("total EPT violation count: %d\n", ept_fault);
}

int main(int argc, char *argv[])
{
	struct kvm_vm *vm;
	struct kvm_run *run;

	prepare_test(&vm, &run);

	setup_spp(vm);

	run_test(vm, run);

	unset_spp(vm);

	vcpu_run(vm, VCPU_ID);

	printf("completed SPP test successfully!\n");

	kvm_vm_free(vm);

	return 0;
}

