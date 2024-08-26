#include <linux/uaccess.h>
#include <linux/bitops.h>
#include <linux/capability.h>
#include <linux/cpu.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/hash.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/skbuff.h>
#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/busy_poll.h>
#include <linux/rtnetlink.h>
#include <linux/stat.h>
#include <net/dst.h>
#include <net/dst_metadata.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/checksum.h>
#include <net/xfrm.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netpoll.h>
#include <linux/rcupdate.h>
#include <linux/delay.h>
#include <net/iw_handler.h>
#include <asm/current.h>
#include <linux/audit.h>
#include <linux/dmaengine.h>
#include <linux/err.h>
#include <linux/ctype.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/mpls.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <trace/events/napi.h>
#include <trace/events/net.h>
#include <trace/events/skb.h>
#include <linux/pci.h>
#include <linux/inetdevice.h>
#include <linux/cpu_rmap.h>
#include <linux/static_key.h>
#include <linux/hashtable.h>
#include <linux/vmalloc.h>
#include <linux/if_macvlan.h>
#include <linux/errqueue.h>
#include <linux/hrtimer.h>
#include <linux/netfilter_ingress.h>
#include <linux/crash_dump.h>
#include <linux/sctp.h>
#include <net/udp_tunnel.h>
#include <linux/net_namespace.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/highmem.h>
#include <linux/slab.h>

#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/inetpeer.h>
#include <net/lwtunnel.h>
#include <linux/bpf-cgroup.h>
#include <linux/igmp.h>
#include <linux/netlink.h>
#include <linux/tcp.h>

#include "br_private.h"
#include <linux/scone.h>

/* void print_iph: Print out the contents of the packet
such as destination/source IP addresses */
void print_iph(struct sk_buff *skb){
  struct iphdr *iph = ip_hdr(skb);

  unsigned long saddr = ntohl( iph->saddr );
  unsigned long daddr = ntohl( iph->daddr );

  printk("SCON: [%s] daddr:%lu.%lu.%lu.%lu, saddr:%lu.%lu.%lu.%lu, tos:%d, smp_processor_id:%d\n", __func__,
  				(daddr & 0xFF000000) >> 24, (daddr & 0x00FF0000) >> 16, (daddr & 0x0000FF00) >> 8, (daddr & 0x000000FF),
  				(saddr & 0xFF000000) >> 24, (saddr & 0x00FF0000) >> 16, (saddr & 0x0000FF00) >> 8, (saddr & 0x000000FF),
  				(int) iph->tos, smp_processor_id());
//  printk("SCON: iph->daddr = %d", iph->daddr);

}
/* struct scone_flow_table* scone_init(): Initialize scone_flow_table data structure
and return the pointer. If the initialize goes wrong return NULL. */
#ifdef FLOW_TABLE
struct scone_flow_table* scone_init(struct sk_buff *skb)
{
  struct iphdr *iph;
  struct scone_flow_table *ft = NULL;
  int err = 0;

  ft = kzalloc(sizeof(struct scone_flow_table), GFP_KERNEL);
  if(ft == NULL){
    printk("SCON: [%s] Failed to allocate flow table memory \n", __func__);
    return NULL;
  }

  ft = memset(ft, 0, sizeof(struct scone_flow_table));
  if (ft == NULL){
    printk("SCON: [%s] Memset Failed \n", __func__);
    return NULL;
  }

/* This re-organize packet data which is essenstial
to find the correct content of the packet*/
#ifndef FCRACKER
  skb_reset_network_header(skb);
#else
  skb_reset_network_header(skb);
  if (!skb_transport_header_was_set(skb))
    skb_reset_transport_header(skb);
  skb_reset_mac_len(skb);
#endif

  iph = ip_hdr(skb);
  if (iph == NULL) {
    printk("SCON: [%s] failed to get ip header information\n", __func__);
    return NULL;
  }
/* Store the information of the packet to the flow table
to utilize the information as a identifier of the flow table. */
  ft->ip_protocol = iph->protocol;
  ft->saddr = iph->saddr;
  ft->daddr = iph->daddr;
	ft->netfilter = 0;
	ft->count = 0;
	ft->xmit_simple = 0;

/* Multiple flow tables are managed using a linked list per a net_bridge_port */
#ifdef MULTI_FT
	INIT_LIST_HEAD(&ft->ctable_list);
#endif
/* This massage is printed once when the flow table is initilized. */
  printk("SCON: [%s] ft = %p, daddr = %d\n", __func__, ft, iph->daddr);
  return ft;
}
EXPORT_SYMBOL(scone_init);

/* This indentifies TCP SYN packet */
int tcp_new_syn (struct sk_buff *skb)
{
	struct iphdr *iph;
	struct tcphdr *tcph;

	iph = ip_hdr(skb);
	
	if (iph->protocol == IPPROTO_TCP) {
		tcph = (struct tcphdr *)(skb_network_header(skb) + ip_hdrlen(skb));

		if ((tcph->syn == 1) && (tcph->ack == 0))
			return 1;
	}

	return 0;
}
EXPORT_SYMBOL(tcp_new_syn);





/* This finds corresponding flow table in the list that belongs to a net_bridge_port
by comparing IP addresses and protocol ID. */
#ifndef MULTI_FT
int find_ft(struct sk_buff *skb, struct scone_flow_table *ft)
#else
int find_ft(struct sk_buff *skb, struct scone_flow_table *ft, struct list_head *head)
#endif
{
	struct iphdr *iph;
  int err = 0;
	struct scone_flow_table *new_ft;

#ifndef FCRACKER
  skb_reset_network_header(skb);
#else
  skb_reset_network_header(skb);
  if (!skb_transport_header_was_set(skb))
    skb_reset_transport_header(skb);
  skb_reset_mac_len(skb);
#endif
  if (skb == NULL || ft == NULL){
    printk("SCON: [%s] skb (%p)or ft (%p) is NULL\n", __func__, skb, ft);
    return err;
}
	iph = ip_hdr(skb);

	if (iph == NULL) {
		printk("SCON: [%s] Failed to get ip header information, skb->protocol=%d\n", __func__, skb->protocol);
    return err;
  }

	if (iph->protocol == ft->ip_protocol && iph->saddr == ft->saddr && iph->daddr == ft->daddr)
			skb->ft = ft;
#ifndef MULTI_FT
	else{
    new_ft = memset(ft, 0, sizeof(struct scone_flow_table));
		if (new_ft == NULL ) {
	    printk("SCON: [%s] memset Failed \n", __func__);
			return err;
	   }
	 	ft->ip_protocol = iph->protocol;
	  ft->saddr = iph->saddr;
		ft->daddr = iph->daddr;
		ft->netfilter = 0;
	}
#else
	else{
		skb->ft=NULL;
		list_for_each_entry(new_ft, head, ctable_list){
			if (iph->protocol == new_ft->ip_protocol && iph->saddr == new_ft->saddr && iph->daddr == new_ft->daddr){
        skb->ft = new_ft;
				printk("SCON: [%s] find the right ft %ld\n", __func__, new_ft->_skb_refdst);
			}
		}
		if(skb->ft == NULL){
/* If there is no match, a new flow table is created. */
			new_ft=scone_init(skb);
			if(new_ft==NULL){
				printk("SCON: [%s] failed to allocation new ft %p\n", __func__, new_ft);
				return err;
			}
			else
        list_add(&new_ft->ctable_list, head);
			skb->ft = new_ft;
		}
	}
#endif
  return 1;
}
EXPORT_SYMBOL(find_ft);
/* This is a wrapper function of find_ft,
which designates target packet to process using shortcut. */
void probe_ft(struct sk_buff *skb)
{
  int err;
#ifndef FCRACKER
  struct net_bridge_port *p = br_port_get_rcu(skb->dev);
#else
  struct net_device *p = skb->dev;
  struct iphdr *iph;
#endif
#ifdef MULTI_FT
	struct scone_flow_table *ft;
#endif

#ifndef FCRACKER
  if(skb==NULL)
    return;
#else
  if(skb==NULL || p==NULL){
    printk("SCON: skb (%p) or p (%p) is NULL \n", skb, p);
    return;
  }
//printk("SCON: [%s] dev = %s\n", __func__, p->name);
#endif

#ifdef FCRACKER
  skb_reset_network_header(skb);
  if (!skb_transport_header_was_set(skb))
    skb_reset_transport_header(skb);
  skb_reset_mac_len(skb);

  iph = ip_hdr(skb);
  if(iph == NULL || iph->daddr == 0 || iph->saddr == 0)
    return;
  if(iph->daddr != 33619978)  //kwlee: This is hard-coded IP address (10.0.1.2) of target flow
    return;
#endif

#ifndef MULTI_FT
  if(p->ft == NULL){
    p->ft = scone_init(skb);
#else
  if(list_empty(&p->ctable_list)){
    p->ft = scone_init(skb);
    if(p->ft == NULL)
      return;
    else
      list_add(&p->ft->ctable_list, &p->ctable_list);
#endif
    skb->ft = p->ft;
  } else {
#ifndef MULTI_FT
      err = find_ft(skb, p->ft);
#else
      err = find_ft(skb, p->ft, &p->ctable_list);
      p->ft = skb->ft;
#endif
  }
  if(err==0){
    printk(KERN_EMERG "SCON: find_ft has error\n");
    return;
  }

#ifdef MULTI_FT
  ft = skb->ft;
  if (ft->_skb_refdst != 0)
    skb->_skb_refdst = ft->_skb_refdst;

#ifdef DST_PASS
  skb->out_dev = ft->out_dev;
  skb->input = ft->input;
#endif
  skb->neigh = ft->neigh;
  skb->netfilter = ft->netfilter;
#endif

//  print_iph(skb);
}
EXPORT_SYMBOL(probe_ft);

#endif /* FLOW_TABLE */
