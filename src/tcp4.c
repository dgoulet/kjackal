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

#include <net/net_namespace.h>
#include <net/tcp.h>

#include "common.h"
#include "module.h"
#include "tcp4.h"

/*
 * Check for seq_ops.show hijack normally used to hide port from user space
 * with netstat accessing /proc.
 */
void kj_tcp4_hijack_detection(void)
{
	int got_tcp = 0, got_mod = 0, ret;
	struct module *mod;
	struct proc_dir_entry *pde;
	struct tcp_seq_afinfo *tcp_afinfo = NULL;
	struct net *glb_net;

	glb_net = get_net(&init_net);

	/* Find TCP proc entry. */
	pde = glb_net->proc_net->subdir;
	do {
		if (strncmp(pde->name, "tcp", sizeof("tcp")) == 0) {
			got_tcp = 1;
			break;
		}
		pde = pde->next;
	} while (pde);

	if (!got_tcp) {
		goto end;
	}

	tcp_afinfo = (struct tcp_seq_afinfo *) pde->data;

	/* Check if the call show points in the kernel text area. */
	ret = kj_is_addr_kernel_text((unsigned long) tcp_afinfo->seq_ops.show);
	if (!ret) {
		DMESG("TCP4 seq_ops show has been changed to %p",
				tcp_afinfo->seq_ops.show);
		/* Let check if is points to a LKM (kernel moduel). */
		kj_module_lock_list();
		mod = kj_module_get_from_addr((unsigned long) tcp_afinfo->seq_ops.show);
		if (mod) {
			DMESG("Module '%s' hijacked it. Probably hidding port(s)",
					mod->name);
			DMESG("Module arguments are '%s'", mod->args);
			kj_module_list_symbols(mod);
			got_mod = 1;
		} else {
			DMESG("Can't find any module containing this addr. It's possible "
					"that the module was deleted from the global module list");
		}
		kj_module_unlock_list();
	}

end:
	put_net(&init_net);

	if (!got_mod) {
		DMESG("No TCP IPv4 hijack detected");
	} else {
		DMESG("TCP IPv4 hijack detection done");
	}
}
