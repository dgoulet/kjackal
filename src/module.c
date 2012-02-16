/*
 * module.c
 *
 * Actions possible on module for the project.
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

#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/module.h>

#include "common.h"
#include "module.h"

static const char *module_memdump_path= "/tmp/rootkit-module.dump";

static struct kset *module_kset_sym;

#define MODULE_INIT_KSET()                                          \
	do {                                                            \
		if (!module_kset_sym) {                                     \
			module_kset_sym = lookup_kernel_symbol("module_kset");  \
		}                                                           \
	} while (0);

#define module_to_kobject(n) container_of(n, struct module_kobject, kobj)

struct module *module_find_hidden_from_addr(unsigned long addr)
{
	int end = 0;
	struct module_kobject *mk;
	struct kobject *k;
	const char *name;

	/* Get modules kset */
	MODULE_INIT_KSET();

	if (!module_kset_sym) {
		DMESG("Unable to find module_kset. Skipping hidden module lookup");
		return NULL;
	}

	/*
	 * Iterate over kobject from the module kset. Try to identify a module
	 * kobject to an unfindable module. If the module was removed from the
	 * global module list, we'll be able to find it from the module kset.
	 */
	list_for_each_entry(k, &module_kset_sym->list, entry) {
		name = kobject_name(k);
		if (!name) {
			/*
			 * For some reason, we have to detect the end of the list or it
			 * goes around infinitely. With end == 1, it's over.
			 */
			if (end) {
				break;
			}
			end++;
		}

		mk = module_to_kobject(k);
		if (!mk || !mk->mod) {
			continue;
		}

		if (addr >= (unsigned long)mk->mod->module_core &&
				addr < (unsigned long)(mk->mod->module_core + mk->mod->core_size)) {
			/*
			 * We have an allocated module name but no module found in the
			 * global list. We got our hidden module! ;).
			 */
			DMESG("Hidden module found: '%s'", mk->mod->name);
			DMESG("Address space from 0x%p to 0x%p", mk->mod->module_core,
					mk->mod->module_core + mk->mod->core_size);
			module_list_symbols(mk->mod);
			return mk->mod;
		}
	}

	return NULL;
}

void module_find_all_hidden(void)
{
	int end = 0;
	struct module_kobject *mk;
	struct kobject *k;
	struct module *mod;
	const char *name;

	/* Get modules kset */
	MODULE_INIT_KSET();

	if (!module_kset_sym) {
		DMESG("Unable to find module_kset. Skipping hidden module lookup");
		return;
	}

	/*
	 * Iterate over kobject from the module kset. Try to identify a module
	 * kobject to an unfindable module. If the module was removed from the
	 * global module list, we'll be able to find it from the module kset.
	 */
	list_for_each_entry(k, &module_kset_sym->list, entry) {
		name = kobject_name(k);
		if (!name) {
			/*
			 * For some reason, we have to detect the end of the list or it
			 * goes around infinitely. With end == 1, it's over.
			 */
			if (end) {
				break;
			}
			end++;
		}

		mk = module_to_kobject(k);
		if (mk && mk->mod && mk->mod->name) {
			module_lock_list();
			mod = find_module(mk->mod->name);
			if (!mod) {
				/*
				 * We have an allocated module name but no module found in the
				 * global list. We got our hidden module! ;).
				 */
				DMESG("Hidden module found: '%s'", mk->mod->name);
				DMESG("Address space from 0x%p to 0x%p", mk->mod->module_core,
						mk->mod->module_core + mk->mod->core_size);
				module_list_symbols(mk->mod);
			}
			module_unlock_list();
		}
	}
}

/*
 * List ELF symbol of the module.
 */
void module_list_symbols(struct module *mod)
{
	int i;

	DMESG("%d internal symbol(s) found", mod->num_symtab);

	printk("rootkit: ");
	for (i = 1; i < mod->num_symtab; i++) {
		printk("%s ", &mod->strtab[mod->symtab[i].st_name]);
	}
	printk("\n");
}

/*
 * __module_address requires us to lock the module mutex or disable premption.
 * Use module_lock_list() for that.
 */
struct module *module_get_from_addr(unsigned long addr)
{
	return  __module_address(addr);
}

/*
 * Dump memory of module to filesystem.
 */
void module_dump_memory(struct module *mod)
{
	mm_segment_t fs;
	u32 bytes_written;
	struct file *fp;

	/* Open memory dump file */
	fp = filp_open(module_memdump_path, O_WRONLY | O_CREAT, S_IRUSR);
	if (IS_ERR(fp) || fp->f_op == NULL) {
		DMESG("[Error]: fail to open %s", module_memdump_path);
		goto error_open;
	}

	/* Write module init section to file */
	fs = get_fs();
	set_fs(get_ds());
	bytes_written = fp->f_op->write(fp, mod->module_init, mod->init_size,
			&(fp->f_pos));
	set_fs(fs);
	if (bytes_written != mod->init_size) {
		DMESG("[Error]: init section write failed, wrote %d bytes expected %d",
				bytes_written, mod->init_size);
		goto error_write;
	}

	/* Write module core section fo file */
	fs = get_fs();
	set_fs(get_ds());
	bytes_written = fp->f_op->write(fp, mod->module_core, mod->core_size,
			&(fp->f_pos));
	set_fs(fs);
	if (bytes_written != mod->core_size) {
		DMESG("[Error]: core section write failed, wrote %d bytes expected %d",
				bytes_written, mod->core_size);
		goto error_write;
	}

error_write:
	filp_close(fp, NULL);

error_open:
	return;
}
