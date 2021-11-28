// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define HOSTNAME_LEN 84

const volatile pid_t target_pid = 0;

/* Copied from: include/netdb.h */
struct addrinfo {
	int ai_flags; /* Input flags.  */
	int ai_family; /* Protocol family for socket.  */
	int ai_socktype; /* Socket type.  */
	int ai_protocol; /* Protocol for socket.  */
	u32 ai_addrlen; /* Length of socket address.  */
	struct sockaddr *ai_addr; /* Socket address for socket.  */
	char *ai_canonname; /* Canonical name for service location.  */
	struct addrinfo *ai_next; /* Pointer to next in list.  */
};

struct lookup {
	char c[84];
	struct addrinfo **results;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct lookup);
} lookups SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct lookup);
} hostnames SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct sock *);
} sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

enum tag { IP = 0, HOSTNAME = 1 };

struct event {
	u8 tag;
	u8 ip[4];
	u8 hostname[HOSTNAME_LEN];
};

/* trigger creation of event struct in skeleton code */
struct event _event = {};

static u32 get_tid()
{
	u64 tgid = bpf_get_current_pid_tgid();
	pid_t pid = tgid >> 32;

	if (target_pid != 0 && target_pid != pid)
		return 0;
	return (u32)tgid;
}

SEC("uprobe/getaddrinfo")
int BPF_KPROBE(getaddrinfo_enter, const char *hostname, const char *service,
	       const struct addrinfo *hints, struct addrinfo **res)
{
	u32 tid = get_tid();
	struct lookup lookup = {};

	if (!tid)
		return 0;
	bpf_probe_read_user_str(&lookup.c, sizeof(lookup.c), hostname);
	lookup.results = res;
	bpf_map_update_elem(&lookups, &tid, &lookup, BPF_ANY);
	return 0;
}

SEC("uretprobe/getaddrinfo")
int BPF_KRETPROBE(getaddrinfo_exit, int ret)
{
	u32 tid = get_tid();
	struct lookup *lookup;
	struct addrinfo *result;
	struct sockaddr_in *addr;
	struct in_addr ipv4_addr;

	if (!tid)
		return 0;
	if (ret != 0)
		goto cleanup;
	lookup = bpf_map_lookup_elem(&lookups, &tid);
	if (!lookup)
		return 0;
	bpf_probe_read_user(&result, sizeof(result), lookup->results);
	bpf_probe_read_user(&addr, sizeof(addr), &result->ai_addr);
	bpf_probe_read_user(&ipv4_addr, sizeof(ipv4_addr), &addr->sin_addr);
	bpf_map_update_elem(&hostnames, &ipv4_addr.s_addr, lookup, BPF_ANY);
cleanup:
	bpf_map_delete_elem(&lookups, &tid);
	return 0;
}


SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect_enter, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	u32 tid = get_tid();

	if (!tid)
		return 0;
	bpf_map_update_elem(&sockets, &tid, &sk, 0);
	return 0;
};

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_exit, int ret)
{
	u32 tid = get_tid();
	struct sock **sockpp;
	struct lookup *lookup;
	struct event event = {};
	u32 ip;

	if (!tid)
		return 0;
	if (ret != 0)
		goto cleanup;
	sockpp = bpf_map_lookup_elem(&sockets, &tid);
	if (!sockpp)
		return 0;
	ip = BPF_CORE_READ(*sockpp, __sk_common.skc_daddr);
	lookup = bpf_map_lookup_elem(&hostnames, &ip);
	if (!lookup) {
		event.tag = IP;
		memcpy(&event.ip, &ip, sizeof(event.ip));
	} else {
		event.tag = HOSTNAME;
		memcpy(&event.hostname, &lookup->c, sizeof(lookup->c));
		bpf_map_delete_elem(&hostnames, &ip);
	}
	/* ctx is implied in the signature macro */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
cleanup:
	bpf_map_delete_elem(&sockets, &tid);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
