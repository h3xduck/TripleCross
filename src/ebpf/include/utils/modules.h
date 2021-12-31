#ifndef __MODULES_H
#define __MODULES_H

#define RETURN_VALUE_MODULE_NONACTIVE -1
//Access user-defined config
#include "../../user/include/modules/module_manager.h"


#define CHECK_MODULE_ACTIVE(module, func)\
    if( module_config. module##_module.all != ON){\
        return RETURN_VALUE_MODULE_NONACTIVE;\
    }

#endif