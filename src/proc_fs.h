/*
 * proc_fs.h
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

#ifndef KJACKAL_PROC_FS_H
#define KJACKAL_PROC_FS_H

#include <linux/proc_fs.h>
#include <linux/version.h>

void kj_procfs_hijack_detection(void);

/*
 * In kernel 3.11.x and later, readdir() has been changed to iterate().
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
static inline
unsigned long kj_get_fop_ptr(struct file *fp)
{
	return (unsigned long) fp->f_op->readdir;
}
#else
static inline
unsigned long kj_get_fop_ptr(struct file *fp)
{
	return (unsigned long) fp->f_op->iterate;
}
#endif	/* LINUX_VERSION_CODE < 3.10.11 */

#endif /* KJACKAL_PROC_FS_H */
