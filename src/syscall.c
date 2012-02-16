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

#ifdef CONFIG_KALLSYMS
#include <linux/kallsyms.h>
#endif

#include "common.h"
#include "module.h"
#include "syscall.h"

#define SYSCALL_TABLE_INIT(void)        \
	do {                                    \
		if (sys_call_table == NULL) {       \
			syscall_init_table();           \
		}                                   \
	} while (0);

static unsigned long *sys_call_table;

/*
 * Detect any syscall address from the global table that is outside kernel text
 * section.
 */
void syscall_hijack_detection(void)
{
	int i, ret, got_hijack = 0;
	struct module *mod;
	unsigned long syscall_addr;

	/* Safety net */
	SYSCALL_TABLE_INIT();

	if (sys_call_table == NULL) {
		DMESG("Unable to get sys_call_table address. Aborting");
		goto end;
	}

	/*
	 * For each syscalls in the table, we'll check if the address is in the
	 * core kernel text area which is suppose to be.
	 */
	for (i = 0; i < NR_syscalls; i++) {
		syscall_addr = sys_call_table[i];

		/*
		 * Is the syscall addr is in kernel text section.
		 */
		ret = is_addr_kernel_text(syscall_addr);
		if (ret) {
			/* Fine for now, continue. */
			continue;
		}

		got_hijack = 1;
		DMESG("Possible syscall number %d hijacked at %p", i,
				(void *) syscall_addr);

		/* Let check if is points to a LKM */
		module_lock_list();
		mod = module_get_from_addr(syscall_addr);
		if (mod) {
			DMESG("Module '%s' controls it at %p", mod->name,
					(void *) syscall_addr);
			DMESG("Module arguments are '%s'", mod->args);
			module_list_symbols(mod);
		} else {
			mod = module_find_hidden_from_addr(syscall_addr);
			if (!mod) {
				DMESG("Can't find any module containing this addr. It's "
						"possible that the module has been erased from the "
						"global module list to hide his self.");
			}
		}
		module_unlock_list();
	}

	if (!got_hijack) {
		DMESG("No syscall hijack detected");
	}

end:
	DMESG("[+] Syscall hijack detection done");
}

/*
 * Dynamically lookup syscall table address.
 */
void syscall_init_table(void)
{
	sys_call_table = lookup_kernel_symbol("sys_call_table");
}
