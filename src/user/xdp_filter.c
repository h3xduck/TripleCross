#include <argp.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <unistd.h>

#include "xdp_filter.skel.h"
#include "include/xdp_filter.h"
#include "../constants/constants.h"

static struct env {
	bool verbose;
} env;

void print_help_dialog(const char* arg){
    printf("\nUsage: %s ./xdp_filter OPTION\n\n", arg);
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

/*static int handle_event(void *ctx, void *data, size_t data_sz){
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    printf("NEW: %s\n",
            e->payload);

	return 0;
}*/


int main(int argc, char**argv){
    //struct ring_buffer *rb = NULL;
    struct xdp_filter_bpf *skel;
    int err;
	
	unsigned int ifindex; 

	/* Parse command line arguments */
	int opt;
	while ((opt = getopt(argc, argv, ":t:vh")) != -1) {
        switch (opt) {
        case 't':
            ifindex = if_nametoindex(optarg);
            printf("Activating filter on network interface: %s\n", optarg);
            if(ifindex == 0){
				perror("Error on input interface");
				exit(EXIT_FAILURE);
			}
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
        
        default:
            print_help_dialog(argv[0]);
            exit(EXIT_FAILURE);
        }
    }
	
	// Set up libbpf errors and debug info callback
	libbpf_set_print(libbpf_print_fn);

	// Bump RLIMIT_MEMLOCK to be able to create BPF maps
	bump_memlock_rlimit();

	// Cleaner handling of Ctrl-C
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

    // Load and verify BPF application
	skel = xdp_filter_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	// Load & verify BPF programs */
	err = xdp_filter_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    // Attach tracepoints
	/*err = xdp_filter_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}*/

	//Attack BPF program to network interface
	int flags = XDP_FLAGS_SKB_MODE;
    int fd = bpf_program__fd(skel->progs.xdp_receive);
    err = bpf_set_link_xdp_fd(ifindex, fd, flags);

	printf("Filter set and ready\n");
	while (!exiting) {
		/* trigger our BPF program */
		fprintf(stderr, ".");
		sleep(1);
	}

	//Received signal to stop, detach program from network interface
	fd = -1;
    err = bpf_set_link_xdp_fd(ifindex, fd, flags);


    cleanup:
        xdp_filter_bpf__destroy(skel);

        return err < 0 ? -err : 0;

    return 0;
}