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
 */
#if defined(CONFIG_KALLSYMS) && defined(CONFIG_KALLSYMS_ALL)

/*
 * kallsyms_lookup_name was re-exported in from 2.6.33 +
 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
void *lookup_kernel_symbol(const char *name)
{
	return (void *) kallsyms_lookup_name(name);
}
#else
/*
 * kallsyms is available but the lookup function is not exported before this
 * kernel version so we simply stop compilation.
 */
#error "Kernel version not compatible (version >= 2.6.33)"
#endif /* LINUX_VERSION_CODE */

#else /* CONFIG_KALLSYMS && CONFIG_KALLSYMS_ALL */
void *lookup_kernel_symbol(const char *name)
{
	void *sym = NULL;

	/*
	 * SYS_CALL_TABLE, MODULE_KSET AND CORE_KERNEL_TEXT are replaced by the
	 * Makefile. Those addresses are red from the System-map-$(uname -r) file.
	 *
	 * DO NOT CHANGE this arbitrarily unles you know what you are doing.
	 */
	if (strcmp(name, "sys_call_table") == 0) {
		sym = (void*)0xSYS_CALL_TABLE;
	} else if (strcmp(name, "module_kset") == 0) {
		sym = (void*)0xMODULE_KSET;
	} else if (strcmp(name, "core_kernel_text") == 0) {
		sym = (void*)0xCORE_KERNEL_TEXT;
	}

	return sym;
}
#endif /* CONFIG_KALLSYMS && CONFIG_KALLSYMS_ALL */

/*
 * Check if addr is in core kernel text.
 *
 * Return 1 if yes, else 0.
 */
int is_addr_kernel_text(unsigned long addr)
{
	if (!__kernel_text_address_sym) {
		__kernel_text_address_sym = lookup_kernel_symbol("core_kernel_text");
	}

	if (__kernel_text_address_sym) {
		return  __kernel_text_address_sym(addr);
	}

	return 1;
}
