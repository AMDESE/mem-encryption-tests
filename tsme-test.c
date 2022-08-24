// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD TSME Test Module
 *
 * Copyright (C) 2020 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/smp.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

#include <asm/tlbflush.h>
#include <asm/special_insns.h>

MODULE_AUTHOR("Advanced Micro Devices, Inc.");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TSME test module");

static unsigned int debug;
module_param(debug, uint, 0444);
MODULE_PARM_DESC(debug, " print extra debug information - any non-zero value");

#undef pr_fmt
#define pr_fmt(fmt)	"TSME Test: " fmt

static int tsme_active;

static ssize_t tsme_show(struct kobject *kobj,
			 struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", !!tsme_active);
}
static struct kobj_attribute tsme_attr = __ATTR_RO(tsme);

static void __flush_all(void *arg)
{
	unsigned long flush_cache = (bool)arg;

	__flush_tlb_all();
	if (flush_cache)
		wbinvd();
}

static void flush_all(unsigned long flush_cache)
{
	on_each_cpu(__flush_all, (void *) flush_cache, 1);
}

static void update_pte(pte_t *ptep, pte_t pte)
{
	flush_all(1);

	set_pte_atomic(ptep, pte);

	flush_all(0);
}

#define RETRY_COUNT 64
static int __init tsme_test_init(void)
{
	unsigned long sme_mask;
	void *buffer, *buffer_reference, *buffers[RETRY_COUNT];
	struct page *page, *page_reference;
	pte_t *ptep, old_pte, new_pte;
	unsigned int level, retry;
	int ret;

	if (cpuid_eax(0x80000000) < 0x8000001f) {
		pr_err("CPUID leaf 0x8000001f is not available, will not be able to determine TSME status\n");
		return -EINVAL;
	}

	if (!(cpuid_eax(0x8000001f) & 1)) {
		pr_err("Memory encryption is not available, will not be able to determine TSME status\n");
		return -EINVAL;
	}

	ret = -ENOMEM;

	sme_mask = BIT_ULL(cpuid_ebx(0x8000001f) & 0x3f);
	if (debug)
		pr_notice("SME status: encryption-mask = %#lx\n", sme_mask);

	retry = 0;
retry:
	page = alloc_page(GFP_KERNEL);
	if (!page)
		goto e_freehuge;

	buffer = page_address(page);
	ptep = lookup_address((unsigned long)buffer, &level);
	if (level != PG_LEVEL_4K) {
		buffers[retry++] = buffer;
		if (retry >= RETRY_COUNT) {
			pr_err("Hugepage repeatedly allocated, unable to determine TSME status\n");
			goto e_freehuge;
		}

		goto retry;
	}
	memset(buffer, 0x00, PAGE_SIZE);

	page_reference = alloc_page(GFP_KERNEL);
	if (!page_reference)
		goto e_free;

	buffer_reference = page_address(page_reference);
	memset(buffer_reference, 0x00, PAGE_SIZE);

	old_pte = *ptep;
	new_pte = __pte(pte_val(*ptep) ^ sme_mask);

	if (debug) {
		pr_notice("%u additional attempts to allocate test capable buffer\n", retry);
		pr_notice("Old PTE = %#lx, New PTE = %#lx\n", pte_val(old_pte), pte_val(new_pte));
		pr_notice("Buffer (C-bit=%u)\n", (bool)(pte_val(old_pte) & sme_mask));
		print_hex_dump(KERN_DEBUG, "TSME Test: Buffer (first 64 bytes - before: ", DUMP_PREFIX_OFFSET, 16, 1, buffer, 64, 1);
	}

	/*
	 * Update the PTE for the buffer to set or clear the encryption mask
	 * depending on whether the encryption mask was already cleared or set.
	 *
	 * This will not actually change the contents of the memory, just change
	 * the attribute of the memory. This fact can then be used to compare
	 * against the reference buffer and determine the state of TSME.
	 */
	update_pte(ptep, new_pte);

	if (debug) {
		pr_notice("Buffer (C-bit=%u)\n", (bool)(pte_val(new_pte) & sme_mask));
		print_hex_dump(KERN_DEBUG, "TSME Test: Buffer (first 64 bytes -  after: ", DUMP_PREFIX_OFFSET, 16, 1, buffer, 64, 1);
	}

	if (memcmp(buffer, buffer_reference, PAGE_SIZE) == 0) {
		/* Buffers match - TSME is active */
		tsme_active = 1;
		pr_notice("TSME is active\n");
	} else {
		/* Buffers don't match - TSME is not active */
		tsme_active = 0;
		pr_notice("TSME is not active\n");
	}

	/* Reset the encryption mask to the original */
	update_pte(ptep, old_pte);

	ret = sysfs_create_file(kernel_kobj, &tsme_attr.attr);
	if (ret)
		pr_err("sysfs_create_file failed: ret=%d\n", ret);

	free_page((unsigned long)buffer_reference);

e_free:
	free_page((unsigned long)buffer);

e_freehuge:
	while (retry) {
		retry--;
		free_page((unsigned long)buffers[retry]);
	}

	return ret;
}

static void __exit tsme_test_exit(void)
{
	sysfs_remove_file(kernel_kobj, &tsme_attr.attr);
}

module_init(tsme_test_init);
module_exit(tsme_test_exit);
