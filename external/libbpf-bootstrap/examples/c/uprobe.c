// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "uprobe.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

/* Find process's base load address. We use /proc/self/maps for that,
 * searching for the first executable (r-xp) memory mapping:
 *
 * 5574fd254000-5574fd258000 r-xp 00002000 fd:01 668759                     /usr/bin/cat
 * ^^^^^^^^^^^^                   ^^^^^^^^
 *
 * Subtracting that region's offset (4th column) from its absolute start
 * memory address (1st column) gives us the process's base load address.
 */
static long get_base_addr() {
	size_t start, offset;
	char buf[256];
	FILE *f;

	f = fopen("/proc/self/maps", "r");
	if (!f)
		return -errno;

	while (fscanf(f, "%zx-%*x %s %zx %*[^\n]\n", &start, buf, &offset) == 3) {
		if (strcmp(buf, "r-xp") == 0) {
			fclose(f); // 401380 //text offset-> 1290 //text VA->401290
						//4199296 //4752 //4199056
			return start - offset;
		}
	}

	fclose(f);
	return -1;
}

/* It's a global function to make sure compiler doesn't inline it. */
int uprobed_function(int a, int b)
{
	return a + b;
}

int main(int argc, char **argv)
{
	struct uprobe_bpf *skel;
	long base_addr, uprobe_offset;
	int err, i;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	bump_memlock_rlimit();

	/* Load and verify BPF application */
	skel = uprobe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	base_addr = get_base_addr();
	if (base_addr < 0) {
		fprintf(stderr, "Failed to determine process's load address\n");
		err = base_addr;
		goto cleanup;
	}

	/* uprobe/uretprobe expects relative offset of the function to attach
	 * to. This offset is relateve to the process's base load address. So
	 * easy way to do this is to take an absolute address of the desired
	 * function and substract base load address from it.  If we were to
	 * parse ELF to calculate this function, we'd need to add .text
	 * section offset and function's offset within .text ELF section.
	 */
	uprobe_offset = (long)&uprobed_function - base_addr;

	/* Attach tracepoint handler */
	skel->links.uprobe = bpf_program__attach_uprobe(skel->progs.uprobe,
							false /* not uretprobe */,
							0 /* self pid */,
							"/proc/self/exe",
							uprobe_offset);
	err = libbpf_get_error(skel->links.uprobe);
	if (err) {
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* we can also attach uprobe/uretprobe to any existing or future
	 * processes that use the same binary executable; to do that we need
	 * to specify -1 as PID, as we do here
	 */
	skel->links.uretprobe = bpf_program__attach_uprobe(skel->progs.uretprobe,
							   true /* uretprobe */,
							   -1 /* any pid */,
							   "/proc/self/exe",
							   uprobe_offset);
	err = libbpf_get_error(skel->links.uretprobe);
	if (err) {
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	for (i = 0; ; i++) {
		/* trigger our BPF programs */
		fprintf(stderr, ".");
		uprobed_function(i, i + 1);
		sleep(1);
	}

cleanup:
	uprobe_bpf__destroy(skel);
	return -err;
}
