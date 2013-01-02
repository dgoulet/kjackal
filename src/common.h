/*
 * common.h
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

#ifndef KJACKAL_COMMON_H
#define KJACKAL_COMMON_H

#define KJ_DMESG(fmt, args...) printk("kjackal: " fmt "\n", ## args);

int kj_is_addr_kernel_text(unsigned long addr);

void *kj_kernel_symbol_lookup(const char *name);

#endif /* KJACKAL_COMMON_H */
