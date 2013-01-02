/*
 * common.c
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

#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/version.h>

#include "common.h"

static int (*__kernel_text_address_sym)(unsigned long addr);

/*
 * Two out of three symbols needed by kjackal needs CONFIG_KALLSYMS_ALL. The
 * fallback is to use System-map-* with the Makefile.
 *
 * kallsyms_lookup_name was re-exported in from 2.6.33 + version.
 */
#if defined(CONFIG_KALLSYMS) && defined(CONFIG_KALLSYMS_ALL) && \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32))
void *kj_kernel_symbol_lookup(const char *name)
{
	return (void *) kallsyms_lookup_name(name);
}

#else /* CONFIG_KALLSYMS ... */

/*
 * Return kernel symbol address for the given symbol name.
 */
void *kj_kernel_symbol_lookup(const char *name)
{
	void *sym = NULL;

	/*
	 * SYS_CALL_TABLE, MODULE_KSET AND CORE_KERNEL_TEXT are replaced by the
	 * Makefile. Those addresses are red from the System-map-$(uname -r) file.
	 *
	 * DO NOT CHANGE this arbitrarily unles you know what you are doing.
	 */
	if (strcmp(name, KJ_SYSCALL_TABLE_SYM) == 0) {
		sym = (void*)0xMARKER_SYS_CALL_TABLE;
	} else if (strcmp(name, KJ_MODULE_KSET_SYM) == 0) {
		sym = (void*)0xMARKER_MODULE_KSET;
	} else if (strcmp(name, KJ_CORE_KERN_TEXT_SYM) == 0) {
		sym = (void*)0xMARKER_CORE_KERNEL_TEXT;
	}

	return sym;
}
#endif /* CONFIG_KALLSYMS && CONFIG_KALLSYMS_ALL && LINUX_VERSION_CODE */

/*
 * Check if addr is in core kernel text.
 *
 * Return 1 if yes, else 0.
 */
int kj_is_addr_kernel_text(unsigned long addr)
{
	if (!__kernel_text_address_sym) {
		__kernel_text_address_sym =
			kj_kernel_symbol_lookup(KJ_CORE_KERN_TEXT_SYM);
	}

	if (__kernel_text_address_sym) {
		return  __kernel_text_address_sym(addr);
	}

	return 1;
}
