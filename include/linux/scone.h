#ifndef __SCONE_H
#define __SCONE_H


#define FLOW_TABLE	//kwlee: Activate SCON for Docker containers
#ifdef FLOW_TABLE
	#define DST_PASS
#endif
#define MULTI_FT	//kwlee: This enables to manage multiple flow tables for a container

#define SIMPLE_PATH	//kwlee: This allows packets to go through shourcut
#ifdef SIMPLE_PATH
    #ifndef SKIP_QOS
        #define SKIP_QOS
    #endif
#endif

/* struct scone_flow_table: A key data structure in scone,
which consists of a list and the require data for SIMPLE_PATH */
struct scone_flow_table {
#ifdef MULTI_FT
        struct list_head ctable_list;
#endif
        unsigned long _skb_refdst;
#ifdef DST_PASS
        int			(*input)(struct sk_buff *);
        struct net_device *out_dev;
        int                 out_mtu;
#endif
        __be32 saddr;
        __be32 daddr;
        __u8 ip_protocol;
        struct neighbour * neigh;
        int netfilter;
        struct net_device	*dev;
        int	xmit_simple;
	int     count;
} ____cacheline_internodealigned_in_smp;

struct scone_flow_table* scone_init(struct sk_buff *skb);
#ifndef MULTI_FT
int find_ft(struct sk_buff *skb, struct scone_flow_table *ft);
#else
int find_ft(struct sk_buff *skb, struct scone_flow_table *ft, struct list_head *head);
#endif
/* scone netfilter */
int scone_simple_netfilter(struct sk_buff *skb);
int tcp_new_syn(struct sk_buff *skb);
#ifdef FLOW_TABLE
void probe_ft(struct sk_buff *skb);
#endif
void print_iph(struct sk_buff *skb);	//kwlee: For debugging
#endif
