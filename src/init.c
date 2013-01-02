/*
 * init.c
 *
 * Entry point for kjackal kernel module.
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

#include "common.h"
#include "proc_fs.h"
#include "syscall.h"
#include "tcp4.h"

#include "module.h"

/*
 * Init module
 */
static int __init kjackal_init(void)
{
	/*
	 * Syscall hijack detection.
	 *
	 * The primary technique is to iterate over the syscall table and test
	 * every address to see if it is in the core kernel text section where it's
	 * suppose to be. If yes, we'll check for a module "hosting" this address.
	 */
	kj_syscall_hijack_detection();

	/*
	 * TCP IPv4 seq_ops hijack detection.
	 *
	 * This technique is often used to hide ports or any sensitive information.
	 * The 'seq_ops.show' is checked here to the core kernel text addr. space.
	 */
	kj_tcp4_hijack_detection();

	/*
	 * /proc filesystem hijack detection.
	 *
	 * The readdir ops of /proc checked.
	 */
	kj_procfs_hijack_detection();

	/*
	 * Finally search for all *hidden* module which tries to remove them self
	 * from existence. kjackal still have some card up his sleeve ;).
	 */
	kj_module_find_all_hidden();

	return 0;
}

/*
 * Cleanup module on unload.
 */
static void __exit kjackal_exit(void)
{
	KJ_DMESG("Truie truie");
}

module_init(kjackal_init);
module_exit(kjackal_exit);

MODULE_AUTHOR("David Goulet");
MODULE_DESCRIPTION("Kjackal Linux Rootkit Scanner");
MODULE_LICENSE("GPL");
