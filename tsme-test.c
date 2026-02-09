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

#include <asm/msr-index.h>
#include <asm/tlbflush.h>
#include <asm/set_memory.h>
#include <asm/special_insns.h>

MODULE_AUTHOR("Advanced Micro Devices, Inc.");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TSME test module");

static int node = NUMA_NO_NODE;
module_param(node, int, 0444);
MODULE_PARM_DESC(node, " allocate memory from the specified node (default is no specific node)");

static unsigned int set_memory;
module_param(set_memory, uint, 0444);
MODULE_PARM_DESC(set_memory, " attempt to use set_memory_{uc,wb} when a page is mapped at 1G");

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

	if (cpu_feature_enabled(X86_FEATURE_INVPCID)) {
		struct { u64 d[2]; } desc = { { 0, 0 } };
		unsigned long type = 2;

		asm volatile("invpcid %[desc], %[type]" : : [desc] "m" (desc), [type] "r" (type) : "memory");
	} else {
		unsigned long cr4, flags;

		raw_local_irq_save(flags);

		asm volatile("mov %%cr4,%0" : "=r" (cr4));
		asm volatile("mov %0,%%cr4" : : "r" (cr4 ^ X86_CR4_PGE) : "memory");
		asm volatile("mov %0,%%cr4" : : "r" (cr4)               : "memory");

		raw_local_irq_restore(flags);
	}

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

#define SYSCFG_SME_SEV		(BIT_ULL(23))
#define SYSCFG_SME_HMK		(BIT_ULL(26))

static int __init tsme_check_prereqs(u64 *syscfg)
{
	bool smee_valid = (cpuid_eax(0x8000001f) & BIT(0)) != 0;
	bool hmkee_valid = (cpuid_eax(0x80000023) & BIT(0)) != 0;
	u64 msr, mask;

	if (debug) {
		pr_notice("SME status: cpuid_eax(0x8000001f)=%#010x\n", cpuid_eax(0x8000001f));
		pr_notice("SME status: cpuid_ebx(0x8000001f)=%#010x\n", cpuid_ebx(0x8000001f));
		pr_notice("SME-MK status: cpuid_eax(0x80000023)=%#010x\n", cpuid_eax(0x80000023));
		pr_notice("SME-MK status: cpuid_ebx(0x80000023)=%#010x\n", cpuid_ebx(0x80000023));
	}

	*syscfg = 0;

	if (!smee_valid) {
		pr_err("Memory encryption is not available, will not be able to determine TSME status\n");
		return -EINVAL;
	}

	mask = SYSCFG_SME_SEV;
	if (hmkee_valid)
		mask |= SYSCFG_SME_HMK;

	rdmsrl(0xc0010010, msr);
	if (debug) {
		pr_notice("SYSCFG status: MSR=%#018llx, mask=%#018llx => %#018llx\n", msr, mask, msr & mask);
	}

	msr &= mask;
	if (!msr) {
		pr_err("Memory encryption has not been enabled by BIOS, will not be able to determine TSME status\n");
		return -EINVAL;
	}

	*syscfg = msr;

	return 0;
}

static int __init tsme_test_init(void)
{
	void *buffer, *buffer_reference;
	pte_t *ptep, old_pte, new_pte;
	unsigned long sme_mask;
	unsigned int level;
	u64 syscfg;
	int ret;

	ret = tsme_check_prereqs(&syscfg);
	if (ret)
		return ret;

	if (syscfg == SYSCFG_SME_SEV) {
		sme_mask = BIT_ULL(cpuid_ebx(0x8000001f) & 0x3f);
		if (debug)
			pr_notice("SME status: encryption-mask = %#018lx\n", sme_mask);
	} else if (syscfg == SYSCFG_SME_HMK) {
		pr_err("SME-MK mode is enabled, will not be able to determine TSME status\n");
		return -EINVAL;
	} else {
		pr_err("Unsupported SME/SME-MK configuration: SYSCFG=%#018llx\n", syscfg);
		return -EINVAL;
	}

	if (node != NUMA_NO_NODE && node >= nr_node_ids) {
		pr_err("Specified node (%u) is higher than the maximum node on the system (%u)\n", node, nr_node_ids - 1);
		return -EINVAL;
	}

	if (node != NUMA_NO_NODE && !node_online(node)) {
		pr_err("Specified node (%u) is not online\n", node);
		return -EINVAL;
	}

	if (debug)
		pr_notice("Buffer to be allocated on node %u\n", node);

	buffer = kzalloc_node(PMD_SIZE, GFP_KERNEL, node);
	if (!buffer) {
		pr_err("Buffer allocation failed, unable to determine TSME status\n");
		return -ENOMEM;
	}

	if (debug)
		pr_notice("Buffer allocated on node %u\n", page_to_nid(virt_to_page(buffer)));

	if (node != NUMA_NO_NODE && node != page_to_nid(virt_to_page(buffer))) {
		pr_err("Buffer not allocated on target node, unable to determine TSME status\n");
		ret = -ENOMEM;
		goto e_free;
	}

	ptep = lookup_address((unsigned long)buffer, &level);
	if (level > PG_LEVEL_2M) {
		if (!set_memory) {
			pr_err("Allocation level (%u) is greater than 2M, unable to determine TSME status\n", level);
			ret = -ENOMEM;
			goto e_free;
		}

		pr_notice("Buffer allocation level is %u, attempting to reduce using set_memory_{uc,wb}\n", level);

		ret = set_memory_uc((unsigned long)buffer, PMD_SIZE / PAGE_SIZE);
		if (ret) {
			pr_err("Setting memory to UC failed, unable to determine TSME status: %d\n", ret);
			goto e_free;
		}

		ret = set_memory_wb((unsigned long)buffer, PMD_SIZE / PAGE_SIZE);
		if (ret) {
			pr_err("Setting memory to WB failed, unable to determine TSME status: %d\n", ret);

			/* Can't change pages back to WB, so leak them */
			return ret;
		}

		ptep = lookup_address((unsigned long)buffer, &level);
		pr_notice("Buffer allocation level is now %u\n", level);

		if (level > PG_LEVEL_2M) {
			pr_err("Allocation level (%u) is still mapped greater than 2M, unable to determine TSME status\n", level);
			goto e_free;
		}
	}

	buffer_reference = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buffer_reference) {
		pr_err("Reference allocation failed, unable to determine TSME status\n");
		goto e_free;
	}

	old_pte = *ptep;
	new_pte = __pte(pte_val(*ptep) ^ sme_mask);

	if (debug) {
		pr_notice("Level=%u, Old PTE = %#018lx, New PTE = %#018lx\n", level, pte_val(old_pte), pte_val(new_pte));
		pr_notice("Buffer (KeyMask=%#018lx)\n", pte_val(old_pte) & sme_mask);
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
		pr_notice("Buffer (KeyMask=%#018lx)\n", pte_val(new_pte) & sme_mask);
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

	kfree(buffer_reference);

e_free:
	kfree(buffer);

	return ret;
}

static void __exit tsme_test_exit(void)
{
	sysfs_remove_file(kernel_kobj, &tsme_attr.attr);
}

module_init(tsme_test_init);
module_exit(tsme_test_exit);
