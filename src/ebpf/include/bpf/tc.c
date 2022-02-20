#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/swab.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>


struct pkt_ctx_t {
    struct cursor *c;
    struct ethhdr *eth;
    struct iphdr *ipv4;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct http_req_t *http_req;
};

SEC("classifier/egress")
int classifier(struct __sk_buff *skb){
	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;
	struct ethhdr *eth = data;
    bpf_printk("Heey\n");
	if (data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_SHOT;

	if (eth->h_proto == ___constant_swab16(ETH_P_IP))
		/*
		 * Packet processing is not implemented in this sample. Parse
		 * IPv4 header, possibly push/pop encapsulation headers, update
		 * header fields, drop or transmit based on network policy,
		 * collect statistics and store them in a eBPF map...
		 */
		return 0;//process_packet(skb);
	else
		return TC_ACT_OK;
}

char _license[4] SEC("license") = "GPL";