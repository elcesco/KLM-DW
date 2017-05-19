#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/hashtable.h>

#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>

// *************************************************************************************
// Hashmap
// *************************************************************************************

// this function returns a unique identifier for the network communication flow.
// for the computation is uses ip src address, ip dest address, src port and dest
// port (for protocols where ports are available, otherwise some  idenitifcation
// characteristics are required.

unsigned int s_flow_map_init(void * p)
{

	DEFINE_HASHTABLE(ip_flow_map, 30);

	return 0;
};

unsigned int rxhook(void *priv,
                    struct sk_buff *skb,
                    const struct nf_hook_state *state)
{
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);

	printk("** IP HEADER ************************");
	// printk(KERN_INFO "IP version       = %d \n", ip_header->version);
	// printk(KERN_INFO "IP Header length = %d \n", ip_header->ihl);
	// printk(KERN_INFO "IP tos           = %d \n", ip_header->tos);
	// printk(KERN_INFO "IP tot_len       = %d \n", ip_header->tot_len);
	// printk(KERN_INFO "IP id            = %d \n", ip_header->id);
	// printk(KERN_INFO "IP frag offset   = %d \n", ip_header->frag_off);
	// printk(KERN_INFO "IP TTL           = %d \n", ip_header->ttl);
	// printk(KERN_INFO "IP protocol      = %d \n", ip_header->protocol);
	// printk(KERN_INFO "IP checksum      = %d \n", ip_header->check);
	printk(KERN_INFO "IP src addr      = %pI4 \n", &ip_header->saddr);
	printk(KERN_INFO "IP dest addr     = %pI4 \n", &ip_header->daddr);

	if (ip_header->ihl > 5) {
		//printk(KERN_INFO "IP Protocol: %d \n", ip_header->protocol);
		printk(KERN_INFO "IP Options are set !!!");
		printk(KERN_INFO "IP Header length: %d \n", ip_header->ihl);
	}

	switch(ip_header->protocol )
	{
		case IPPROTO_ICMP: { /* ICMP traffic */
			struct icmphdr *icmp_header;
			icmp_header = (struct icmphdr *)
				((char*) ip_header + (ip_header->ihl*4));

			printk("IP IHL: %d \n", ip_header->ihl);
			// printk("Address of ip_header:   %p \n", ip_header);
			// printk("Address of icmp_header: %p \n", icmp_header);

			printk(KERN_INFO "ICMP packet type:     %d \n",icmp_header->type);
			printk(KERN_INFO "ICMP packet code:     %d \n", icmp_header->code);
			printk(KERN_INFO "ICMP packet checksum: %d \n", icmp_header->checksum);
			break;
		}

		case IPPROTO_TCP: { /* TCP traffic */
			struct tcphdr *tcp_header;
			tcp_header = (struct tcphdr *)
				((char*) ip_header + (ip_header->ihl * 4));
			printk(KERN_INFO "TCP src port:         %u \n", (unsigned int) ntohs(tcp_header->source));
			printk(KERN_INFO "TCP dest port:        %u \n", (unsigned int) ntohs(tcp_header->dest));
			break;
		}

		case IPPROTO_UDP: { /* UDP traffic */
			struct udphdr *udp_header;
			udp_header = (struct udphdr *)
				((char*)ip_header + (ip_header->ihl*4));
			printk(KERN_INFO "UDP src port:          %u \n", (unsigned int) ntohs(udp_header->source));
			printk(KERN_INFO "UDP dest port:         %u \n", (unsigned int) ntohs(udp_header->dest));
			break;
		}

		default:
			//printk("rxhook: Unknown protocol type in ip header : %d\n", 
			//	ip_header->protocol );
			break;
	}

        return NF_ACCEPT;
};

unsigned int txhook(void *priv,
                    struct sk_buff *skb,
                    const struct nf_hook_state *state)
{
	//printk("txhook\n");
        return NF_ACCEPT;
};

static struct nf_hook_ops rxmodule = {
    .hook       = rxhook,
//    .dev        = ,
//    .priv       = ,
    .pf         = PF_INET,
    .hooknum    = NF_INET_PRE_ROUTING,
    .priority   = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops txmodule = {
    .hook       = txhook,
    .hooknum    = NF_INET_LOCAL_OUT,
    .pf         = PF_INET,
    .priority   = NF_IP_PRI_FIRST,
};

static int __init baseInit(void)
{
	printk("baseInit\n");
	nf_register_hook(&rxmodule);
	nf_register_hook(&txmodule);

	return 0;
};

void __exit baseExit(void)
{
	printk("baseExit\n");
	nf_unregister_hook(&rxmodule);
	nf_unregister_hook(&txmodule);
};

module_init(baseInit);
module_exit(baseExit);

MODULE_AUTHOR("Francesco Sole");
MODULE_DESCRIPTION("Sampling Dynamic Warden - Kernel Module");
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");
