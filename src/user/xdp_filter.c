#include <argp.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include "xdp_filter.skel.h"
#include "xdp_filter.h"
#include <net/if.h>

static struct env {
	bool verbose;
} env;

const char *argp_program_version = "xdp_filter 0.1";
const char *argp_program_bug_address = "<marcossanchezbajo@gmail.com>";
const char argp_program_doc[] =
"My first eBPF packet filter using Express Data Path (XDP)\n"
"\n"
"TODO DESCRIPTION\n"
"\n"
"USAGE: ./xdp_filter [-v]\n";

/*Options for argp*/
static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

/*Command argument parsing, similar to getopt*/
static error_t parse_arg(int key, char *arg, struct argp_state *state){
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

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
	
	unsigned int ifindex = if_nametoindex(argv[1]);

	/* Parse command line arguments */
	/*err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;*/

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

    /* Load and verify BPF application */
	skel = xdp_filter_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = xdp_filter_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    /* Attach tracepoints */
	err = xdp_filter_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	int flags = XDP_FLAGS_SKB_MODE;
    int fd = bpf_program__fd(skel->progs.xdp_receive);

    err = bpf_set_link_xdp_fd(ifindex, fd, flags);

    /* Set up ring buffer polling */
	/*rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}*/

    	/* Process events */
	printf("%-8s %-5s %-16s %-7s %-7s %s\n",
	       "TIME", "EVENT", "COMM", "PID", "PPID", "FILENAME/EXIT CODE");
	while (!exiting) {
		//err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

	fd = -1;
    err = bpf_set_link_xdp_fd(ifindex, fd, flags);

    cleanup:
        /* Clean up */
        //ring_buffer__free(rb);
        xdp_filter_bpf__destroy(skel);

        return err < 0 ? -err : 0;

    return 0;
}