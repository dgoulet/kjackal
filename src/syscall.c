/*
 * syscall.c
 *
 * Check for syscall table hijack by looking at each address and validating
 * that the address is pointing to the core kernel text area.
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
#include <linux/mutex.h>
#include <asm/unistd.h>
#include <linux/syscalls.h>
#include <asm/asm-offsets.h>

#ifdef CONFIG_KALLSYMS
#include <linux/kallsyms.h>
#endif

#include "common.h"
#include "module.h"
#include "syscall.h"

#define KJ_SYSCALL_TABLE_INIT(void)        \
	do {                                    \
		if (__sys_call_table_ptr == NULL) {       \
			init_syscall_table();           \
		}                                   \
	} while (0);

static unsigned long *__sys_call_table_ptr;

/*
 * Dynamically lookup syscall table address.
 */
static void init_syscall_table(void)
{
	__sys_call_table_ptr = kj_kernel_symbol_lookup(KJ_SYSCALL_TABLE_SYM);
}

/*
 * Detect any syscall address from the global table that is outside kernel text
 * section.
 */
void kj_syscall_hijack_detection(void)
{
	int i, ret, got_hijack = 0;
	struct module *mod;
	unsigned long syscall_addr;

	/* Safety net */
	KJ_SYSCALL_TABLE_INIT();

	if (__sys_call_table_ptr == NULL) {
		KJ_DMESG("Unable to get sys_call_table address. Aborting");
		goto end;
	}

	/*
	 * For each syscalls in the table, we'll check if the address is in the
	 * core kernel text area which is suppose to be.
	 */
	for (i = 0; i < NR_syscalls; i++) {
		syscall_addr = __sys_call_table_ptr[i];

		/* Is the syscall addr is in kernel text section. */
		ret = kj_is_addr_kernel_text(syscall_addr);
		if (ret) {
			/* Fine for now, continue. */
			continue;
		}

		got_hijack = 1;
		KJ_DMESG("Syscall number %d has been changed to %p", i,
				(void *) syscall_addr);

		/* Let check if is points to a LKM */
		kj_module_lock_list();
		mod = kj_module_get_from_addr(syscall_addr);
		if (mod) {
			KJ_DMESG("Module '%s' controls it at %p", mod->name,
					(void *) syscall_addr);
			KJ_DMESG("Module arguments are '%s'", mod->args);
			kj_module_list_symbols(mod);
		} else {
			mod = kj_module_find_hidden_from_addr(syscall_addr);
			if (!mod) {
				KJ_DMESG("Can't find any module containing this addr. It's "
						"possible that the module was deleted from the "
						"global module list to hide its self.");
			}
		}
		kj_module_unlock_list();
	}

	if (!got_hijack) {
		KJ_DMESG("No syscall hijack detected");
	} else {
		KJ_DMESG("Syscall hijack detection done");
	}

end:
	return;
}
