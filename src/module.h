/*
 * module.h
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

#ifndef KJACKAL_MODULE_H
#define KJACKAL_MODULE_H

#include <linux/module.h>

#include "common.h"

#define KJ_MODULE_INIT_KSET()                                              \
	do {                                                                   \
		if (!module_kset_sym) {                                            \
			module_kset_sym = kj_kernel_symbol_lookup(KJ_MODULE_KSET_SYM); \
		}                                                                  \
	} while (0);

#define KJ_MODULE_TO_KOBJECT(n) container_of(n, struct module_kobject, kobj)

static inline void kj_module_unlock_list(void)
{
	mutex_lock(&module_mutex);
}

static inline void kj_module_lock_list(void)
{
	mutex_unlock(&module_mutex);
}

void kj_module_list_symbols(struct module *mod);
struct module *kj_module_get_from_addr(unsigned long addr);

void kj_module_find_all_hidden(void);
struct module *kj_module_find_hidden_from_addr(unsigned long addr);

#endif /* KJACKAL_MODULE_H */
