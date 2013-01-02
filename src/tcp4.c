/*
 * tcp4.c
 *
 * Check for tcp4 seq_ops hijack.
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

#include <net/tcp.h>
#include <net/net_namespace.h>

#include "common.h"
#include "module.h"
#include "tcp4.h"

/*
 * Check for seq_ops.show hijack normally used to hide port from user space
 * with netstat accessing /proc.
 */
void tcp4_hijack_detection(void)
{
	int got_tcp = 0, got_mod = 0, ret;
	struct module *mod;
	struct proc_dir_entry *my_dir_entry;
	struct tcp_seq_afinfo *my_afinfo = NULL;
	struct net *glb_net;

	glb_net = get_net(&init_net);

	my_dir_entry = glb_net->proc_net->subdir;

	/*
	 * Find TCP proc entry.
	 */
	do {
		if (strncmp(my_dir_entry->name, "tcp", sizeof("tcp")) == 0) {
			got_tcp = 1;
			break;
		}
		my_dir_entry = my_dir_entry->next;
	} while (my_dir_entry != NULL);

	if (!got_tcp) {
		goto end;
	}

	my_afinfo = (struct tcp_seq_afinfo*)my_dir_entry->data;

	ret = is_addr_kernel_text((unsigned long)my_afinfo->seq_ops.show);
	if (!ret) {
		/* Let check if is points to a LKM */
		module_lock_list();
		mod = module_get_from_addr((unsigned long)my_afinfo->seq_ops.show);
		if (mod) {
			DMESG("Module '%s' hijacked tcp4_seq_show."
					" Probably hidding port from user space", mod->name);
			DMESG("Module arguments are '%s'", mod->args);
			module_list_symbols(mod);
			got_mod = 1;
		} else {
			DMESG("Can't find any module containing this addr. It's possible "
					"that the module has been erased from the global module "
					"list to hide his self.");
		}
		module_unlock_list();
	}

end:
	put_net(&init_net);

	if (!got_mod) {
		DMESG("No tcp4 hijack detected");
	}

	DMESG("[+] TCP IPv4 hijack detection done");
}
