#include "module_manager.h"
#include "xdp.h"
#include "sched.h"
#include "fs.h"
#include "exec.h"
#include "injection.h"

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
        .tp_sys_enter_read = OFF,
        .tp_sys_exit_read = OFF,
        .tp_sys_enter_openat = OFF
    },
    .exec_module = {
        .all = ON,
        .tp_sys_enter_execve = OFF
    },
    .injection_module = {
        .all = ON,
        .sys_enter_timerfd_settime = OFF,
        .sys_exit_timerfd_settime = OFF
    }

};

module_config_attr_t module_config_attr = {
    .skel = NULL,
    .xdp_module = {
        .ifindex = -1,
        .flags = -1
    },
    .sched_module = {},
    .fs_module = {},
    .exec_module = {},
    .injection_module = {}
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
        if(config.fs_module.tp_sys_enter_read == ON) ret = attach_tp_sys_enter_read(attr.skel);
        if(config.fs_module.tp_sys_exit_read == ON) ret = attach_tp_sys_exit_read(attr.skel);
        if(config.fs_module.tp_sys_enter_openat == ON) ret = attach_tp_sys_enter_openat(attr.skel);
    }
    if(ret!=0) return -1;

    //EXEC
    if(config.exec_module.all == ON){
        ret = attach_exec_all(attr.skel);
    }else{
        if(config.exec_module.tp_sys_enter_execve == ON) ret = attach_tp_sys_enter_execve(attr.skel);
    }
    if(ret!=0) return -1;

    //INJECTION
    if(config.injection_module.all == ON){
        ret = attach_injection_all(attr.skel);
    }else{
        if(config.injection_module.sys_enter_timerfd_settime == ON) ret = attach_sys_enter_timerfd_settime(attr.skel);
        if(config.injection_module.sys_exit_timerfd_settime == ON) ret = attach_sys_exit_timerfd_settime(attr.skel);
    }
    if(ret!=0) return -1;

    return 0;
}

int activate_all_modules_config(){
    //XDP
    module_config.xdp_module.all = ON;

    //SCHED
    module_config.sched_module.all = ON; 

    //FS (File system)
    module_config.fs_module.all = ON;

    //EXEC
    module_config.exec_module.all = ON;

    return 0;
}

int deactivate_all_modules_config(){
    //XDP
    module_config.xdp_module.all = OFF;

    //SCHED
    module_config.sched_module.all = OFF; 

    //FS (File system)
    module_config.fs_module.all = OFF;

    //EXEC
    module_config.exec_module.all = OFF;

    return 0;
}

int unhook_all_modules(){
    //Alias
    module_config_attr_t attr = module_config_attr;
    int ret;

    //XDP
    ret = detach_xdp_all(attr.skel);
    if(ret!=0) return -1;

    //SCHED
    ret = detach_sched_all(attr.skel);
    if(ret!=0) return -1;

    //FS (File system)
    ret = detach_fs_all(attr.skel);
    if(ret!=0) return -1;

    //EXEC
    detach_exec_all(attr.skel);
    if(ret!=0) return -1;

    return 0;    
}
