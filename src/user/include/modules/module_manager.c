#include "module_manager.h"

module_config_t module_config = {
    .xdp_module = {
        .all = ON,
        .xdp_receive = ON
    },
    .sched_module = {
        .all = ON,
        .handle_sched_process_exec = ON
    }
};
