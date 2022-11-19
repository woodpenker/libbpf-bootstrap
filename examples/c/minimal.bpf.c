// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "helps.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

DEFINE_RO_ARG(my_pid, int, 0);

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	int my_pid = 0;
	READ_ARG_INTO(my_pid);
	if (pid != my_pid)
		return 0;

	bpf_printk("BPF triggered from PID %d.\n", pid);

	return 0;
}
