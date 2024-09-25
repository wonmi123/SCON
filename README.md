# SCON

SCON is a high-performance container networking accelerator for the Linux kernel that maintains interoperability, which is crucial for resource-restricted IoT devices. 
SCON enhances container network efficiency by intelligently memorizing packet processing decisions, all without relying on specific hardware.

## Modified files
The following files have been modified, with changes marked by #ifdef FLOW_TABLE or #ifdef SIMPLE_PATH:
- include/linux/skbuff.h, netdevice.h
- include/net/ip.h
- net/bridge/br_private.h, br_if.c, br_input.c
(BRIDGE module should be included as built-in kernel)
- net/ipv4/ip_output.c, arp.c
- net/sched/sch_generic.c
- net/core/dev.c, skbuff.c
- net/netfilter/nf_nat_core.c
(NF_NAT should be configured as "m")

*How to: make menuconfig -> Networking Option -> Set "Netfilter connection tracking support" to "*"
-> Set "Netfilter Network Address Translation" to "*" 

## Newly added files
The following files have been newly added:
- include/linux/scone.h
- net/bridge/scone.c

## How to deactivate SCON
To deactivate SCON, uncomment the following configurations in include/linux/scone.h:
1) FLOW_TABLE
2) MULTI_FT
3) SIMPLE_PATH

## Citation

```
@article{choi2024intelligent,
  title={Intelligent Packet Processing for Performant Containers in IoT},
  author={Choi, Wonmi and Yoo, Yeonho and Lee, Kyungwoon and Niu, Zhixiong and Cheng, Peng and Xiong, Yongqiang and Yang, Gyeongsik and Yoo, Chuck},
  journal={IEEE Internet of Things Journal},
  year={2024},
  publisher={IEEE}
}
```
