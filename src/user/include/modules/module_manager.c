#include "module_manager.h"
#include "xdp.h"
#include "sched.h"
#include "fs.h"

module_config_t module_config = {
    .xdp_module = {
        .all = ON,
        .xdp_receive = OFF
    },
    .sched_module = {
        .all = ON,
        .handle_sched_process_exec = OFF
    },
    .fs_module = {
        .all = ON,
        .kprobe_ksys_read = OFF,
        .kretprobe_vfs_read = OFF
    }

};

module_config_attr_t module_config_attr = {
    .skel = NULL,
    .xdp_module = {
        .ifindex = -1,
        .flags = -1
    },
    .sched_module = {},
    .fs_module = {}
};


int setup_all_modules(){
    //Alias
    module_config_t config = module_config;
    module_config_attr_t attr = module_config_attr;
    int ret;

    //XDP
    if(config.xdp_module.all == ON){
        ret = attach_xdp_all(attr.skel, attr.xdp_module.ifindex, attr.xdp_module.flags);
    }else{
        if(config.xdp_module.xdp_receive == ON) ret = attach_xdp_receive(attr.skel, attr.xdp_module.ifindex, attr.xdp_module.flags);
    }
    if(ret!=0) return -1;

    //SCHED
    if(config.sched_module.all == ON){
        ret = attach_sched_all(attr.skel);
    }else{
        if(config.sched_module.handle_sched_process_exec == ON) ret = attach_handle_sched_process_exec(attr.skel);
    }
    if(ret!=0) return -1;

    //FS (File system)
    if(config.fs_module.all == ON){
        ret = attach_fs_all(attr.skel);
    }else{
        if(config.fs_module.kprobe_ksys_read == ON) ret = attach_kprobe_ksys_read(attr.skel);
        if(config.fs_module.kretprobe_vfs_read == ON) ret = attach_kretprobe_vfs_read(attr.skel);
    }
    if(ret!=0) return -1;


    return 0;
}
