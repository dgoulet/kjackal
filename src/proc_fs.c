/*
 * proc_fs.c
 *
 * Scans the proc filesystem for potential hijack.
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
#include "module.h"
#include "proc_fs.h"

/*
 * Check for /proc read dir file operation hijack.
 */
void kj_procfs_hijack_detection(void)
{
	int ret, got_mod = 0;
	unsigned long fop_ptr;
	struct file *fp;
	struct module *mod;

	/* Open /proc */
	fp = filp_open("/proc", O_RDONLY, S_IRUSR);
	if (IS_ERR(fp)) {
		KJ_DMESG("[Error]: fail to open /proc");
		goto error_open;
	}

	if (!fp->f_op) {
		KJ_DMESG("[Warn]: /proc file pointer does not have operations");
		goto error_fop;
	}

	fop_ptr = kj_get_fop_ptr(fp);

	ret = kj_is_addr_kernel_text(fop_ptr);
	if (!ret) {
		KJ_DMESG("/proc read dir was changed to %lx", fop_ptr);

		kj_module_lock_list();
		mod = kj_module_get_from_addr(fop_ptr);
		if (mod) {
			KJ_DMESG("Module '%s' hijacked it. Probably hidding PID."
					, mod->name);
			KJ_DMESG("Module arguments are '%s'", mod->args);
			kj_module_list_symbols(mod);
			got_mod = 1;
		}
		kj_module_unlock_list();
	}

	if (!got_mod) {
		KJ_DMESG("No /proc read dir hijack detected");
	} else {
		KJ_DMESG("/proc read dir hijack detection done");
	}

error_fop:
	filp_close(fp, NULL);
error_open:
	return;
}
