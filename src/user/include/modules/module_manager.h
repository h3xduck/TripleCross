#ifndef __MOD_MANAGER_H
#define __MOD_MANAGER_H

#include <stdint.h>

#define ON 1
#define OFF 0

//Centralized configutation struct
typedef struct module_config_t{
    struct xdp_module {
        char all;
        char xdp_receive;
    } xdp_module;

    struct sched_module {
        char all;
        char handle_sched_process_exec;
    }sched_module;

} module_config_t;

extern module_config_t module_config;



#endif