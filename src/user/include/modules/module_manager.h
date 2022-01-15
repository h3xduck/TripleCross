#ifndef __MOD_MANAGER_H
#define __MOD_MANAGER_H

#include <stdint.h>
#include <unistd.h>
#include <linux/types.h>


#define ON 1
#define OFF 0

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
        char kprobe_ksys_read;
        char kretprobe_vfs_read;
    }fs_module;

} module_config_t;

//Configuration struct. Used by the module manager to
//correctly attach the needed modules, providing necessary params
typedef struct module_config_attr_t{
    struct xdp_filter_bpf *skel;
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

#endif