/*
 * open-hijack.c
 *
 * Very simple kernel module that hijacks the open() syscall in the kernel
 * system call table. 
 *
 * Compile the module with 'make' and simply insmod open-hijack.ko. You'll see
 * the debug output in dmesg.
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
#include <asm/unistd.h>
#include <linux/syscalls.h>
#include <linux/vmalloc.h>

static void **sys_call_table;

asmlinkage int (*orig_open)(void);

asmlinkage int hook_open(void)
{
	return orig_open();
}

void hook_syscalls(void)
{
	orig_open = sys_call_table[__NR_open];

	sys_call_table[__NR_open] = hook_open;
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
	sys_call_table = get_writable_sct((void *)0xSYS_CALL_TABLE);

	hook_syscalls();

	printk("Simple mod: orig %p new addr %p\n", orig_open, hook_open);

	/*
	 * Hide the module and prevent it from being removed. Becareful with that
	 * since after that, the module can not be removed with rmmod so you'll
	 * have to basically reboot or write a kernel module that does the trick.
	 * However, kjackal detect the module event if deleted from the global
	 * module list.
	 */

	//list_del(&THIS_MODULE->list);

	return 0;
}

void cleanup_module(void)
{
	sys_call_table[__NR_open] = orig_open;
}

MODULE_LICENSE("GPL");
