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

#ifdef CONFIG_KALLSYMS

/*
 * kallsyms_lookup_name was re-exported in from 2.6.33 +
 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
void *lookup_kernel_symbol(const char *name)
{
	return (void *) kallsyms_lookup_name(name);
}
#else
#error "Kernel version not compatible (version >= 2.6.33)"
#endif /* LINUX_VERSION_CODE */

#endif /* CONFIG_KALLSYMS */

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
