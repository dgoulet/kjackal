/*
 * tcp4.h
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

#ifndef KJACKAL_TCP4_H
#define KJACKAL_TCP4_H

#include <linux/version.h>

#include <net/net_namespace.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
/*
 * XXX: Since kernel 3.10.0, this structure became internal to the kernel thus
 * copying it here so we can access attributes.
 */
struct proc_dir_entry {
	unsigned int low_ino;
	umode_t mode;
	nlink_t nlink;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	const struct inode_operations *proc_iops;
	const struct file_operations *proc_fops;
	struct proc_dir_entry *next, *parent, *subdir;
	void *data;
	atomic_t count;     /* use count */
	atomic_t in_use;    /* number of callers into module in progress; */
	/* negative -> it's going away RSN */
	struct completion *pde_unload_completion;
	struct list_head pde_openers;   /* who did ->open, but not ->release */
	spinlock_t pde_unload_lock; /* proc_fops checks and pde_users bumps */
	u8 namelen;
	char name[];
};
#endif /* LINUX_VERSION_CODE */

void kj_tcp4_hijack_detection(void);

#endif /* KJACKAL_TCP4_H */
