/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
* Method: sr_init(void)
* Scope:  Global
*
* Initialize the routing subsystem
*
*---------------------------------------------------------------------*/
void sr_init(struct sr_instance *sr)
{
	/* REQUIRES */
	assert(sr);

	/* Initialize cache and cache cleanup thread */
	sr_arpcache_init(&(sr->cache));

	pthread_attr_init(&(sr->attr));
	pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_t thread;

	pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

	/* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
* Method: ip_black_list(struct sr_ip_hdr *iph)
* Scope:  Local
*
* This method is called each time the sr_handlepacket() is called.
* Block IP addresses in the blacklist and print the log.
* - Format : "[IP blocked] : <IP address>"
* - e.g.) [IP blocked] : 10.0.2.100
*
*---------------------------------------------------------------------*/
int ip_black_list(struct sr_ip_hdr *iph)
{
	int blk = 0;
	char ip_blacklist[20] = "10.0.2.0"; /* DO NOT MODIFY */
	char mask[20] = "255.255.255.0"; /* DO NOT MODIFY */
	/**************** fill in code here *****************/
	/* convert string to IP */
    uint32_t blk_ip  = inet_addr(ip_blacklist);
    uint32_t netmask = inet_addr(mask);

    /* source IP from packet (already in network byte order) */
    uint32_t src_ip = iph->ip_src;
	uint32_t dst_ip = iph->ip_dst;

    struct in_addr addr;
	/* check whether source IP is in blacklist subnet */
    if ((src_ip & netmask) == (blk_ip & netmask))
    {
        blk = 1;

        /* print message */
        addr.s_addr = src_ip;
        printf("[IP blocked] : %s\n", inet_ntoa(addr));
    }

	else if ((dst_ip & netmask) == (blk_ip & netmask))
	{
		blk = 1;
		addr.s_addr = dst_ip;
		printf("[IP blocked] : %s\n", inet_ntoa(addr));
	}

	/****************************************************/
	return blk;
}
/*---------------------------------------------------------------------
* Method: sr_handlepacket(uint8_t* p,char* interface)
* Scope:  Global
*
* This method is called each time the router receives a packet on the
* interface.  The packet buffer, the packet length and the receiving
* interface are passed in as parameters. The packet is complete with
* ethernet headers.
*
* Note: Both the packet buffer and the character's memory are handled
* by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
* packet instead if you intend to keep it around beyond the scope of
* the method call.
*
*---------------------------------------------------------------------*/
void sr_handlepacket(struct sr_instance *sr,
					 uint8_t *packet /* lent */,
					 unsigned int len,
					 char *interface /* lent */)
{

	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

    /*
        We provide local variables used in the reference solution.
        You can add or ignore local variables.
    */
	uint8_t *new_pck;	  /* new packet */
	unsigned int new_len; /* length of new_pck */

	unsigned int len_r; /* length remaining, for validation */
	uint16_t checksum;	/* checksum, for validation */

	struct sr_ethernet_hdr *e_hdr0, *e_hdr; /* Ethernet headers */
	struct sr_ip_hdr *i_hdr0, *i_hdr;		/* IP headers */
	struct sr_arp_hdr *a_hdr0, *a_hdr;		/* ARP headers */
	struct sr_icmp_hdr *ic_hdr0;			/* ICMP header */
	struct sr_icmp_t0_hdr *ict0_hdr;		/* ICMP type0 header */
	struct sr_icmp_t3_hdr *ict3_hdr;		/* ICMP type3 header */
	struct sr_icmp_t11_hdr *ict11_hdr;		/* ICMP type11 header */

	struct sr_if *ifc;			  /* router interface */
	/*uint32_t ipaddr;*/			  /* IP address */
	struct sr_rt *rtentry;		  /* routing table entry */
	struct sr_arpentry *arpentry; /* ARP table entry in ARP cache */
	struct sr_arpreq *arpreq;	  /* request entry in ARP cache */
	struct sr_packet *en_pck;	  /* encapsulated packet in ARP cache */

	/* validation */
	if (len < sizeof(struct sr_ethernet_hdr))
		return;
	len_r = len - sizeof(struct sr_ethernet_hdr);
	e_hdr0 = (struct sr_ethernet_hdr *)packet; /* e_hdr0 set */

	/* IP packet arrived */
	if (e_hdr0->ether_type == htons(ethertype_ip)) /*jy - ethertype_ip 어디에 선언된 것? - sr_protocol.h에 */
	{
		/* validation */
		if (len_r < sizeof(struct sr_ip_hdr))
			return;

		len_r = len_r - sizeof(struct sr_ip_hdr);
		i_hdr0 = (struct sr_ip_hdr *)(((uint8_t *)e_hdr0) + sizeof(struct sr_ethernet_hdr)); /* i_hdr0 set */

		if (i_hdr0->ip_v != 0x4)
			return;

		checksum = i_hdr0->ip_sum;
		i_hdr0->ip_sum = 0;
		if (checksum != cksum(i_hdr0, sizeof(struct sr_ip_hdr))) /*jy - cksum 어디에 선언된 것? - sr_utils.c*/
			return;
		i_hdr0->ip_sum = checksum; /*jy - 이건 왜 또 적어주는 것? - 원래 헤더에 들어 있던 체크섬 값을 되돌려 넣어주는 것*/

		/* check destination **이 IP 패킷이 나를 향한 것인지 아닌지 체크*/
		for (ifc = sr->if_list; ifc != NULL; ifc = ifc->next)
		{
			if (i_hdr0->ip_dst == ifc->ip)
				break;
		}

		/* check ip black list */
		if (ip_black_list(i_hdr0))
		{
			/* Drop the packet */
			return;
		}

		/* destined to router interface ** 나를 향한 것*/
		if (ifc != NULL)
		{
			/* with ICMP */
			if (i_hdr0->ip_p == ip_protocol_icmp) /* jy - ip_protocol_icmp는 어디에 정의된 것? ip_p는 또 뭐지- ip_p = ip_protocol */
			{
				/* validation */
				if (len_r < sizeof(struct sr_icmp_hdr)) /* ** 이거 다음에는 len_R 새롭게 계산 안 하는 이유? payload 길이는 정해진 게 아니라서? - validation:
   len_r는 IP header 이후 남은 전체 길이를 의미함.
   여기서는 ICMP header가 최소한 존재하는지만 검사하면 되므로,
   ICMP payload 길이는 아직 계산할 필요가 없음.
   따라서 len_r를 추가로 줄이지 않는다.*/
					return;

				ic_hdr0 = (struct sr_icmp_hdr *)(((uint8_t *)i_hdr0) + sizeof(struct sr_ip_hdr)); /* ic_hdr0 set */

				/* echo request type */
				if (ic_hdr0->icmp_type == 0x08)
				{
					/* generate ICMP echo reply packet*/
					new_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t0_hdr);
					new_pck = (uint8_t *) calloc(1, new_len);

					/* validation */
					checksum = ic_hdr0->icmp_sum;
					ic_hdr0->icmp_sum = 0;
					if (checksum != cksum(ic_hdr0, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr)))
						return;
					ic_hdr0->icmp_sum = checksum;
					/****free 어디서? */
					/**************** fill in code here(1) *****************/

					/* ICMP header*/
					ict0_hdr = (struct sr_icmp_t0_hdr*)(new_pck + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

					/**TYPE: 0 = echo reply*/
					ict0_hdr->icmp_type = 0;
					ict0_hdr->icmp_code = 0;

					/*** request payload를 그대로 복사 **고민 1. 왜 len - sizeof(struct sr_ethernet_hdr) 쓰면 안 되는지 2. i_hdr0->ip_len에 대해서 ntohs 해야 하는 이유*/
					memcpy(&ict0_hdr->icmp_identifier, ((uint8_t*)ic_hdr0 + sizeof(struct sr_icmp_hdr)), len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr) - sizeof(struct sr_icmp_hdr));
					
					/**ICMP 헤더 체크섬 계산 */
					ict0_hdr->icmp_sum = 0;
					ict0_hdr->icmp_sum = cksum(ict0_hdr, new_len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));
					
					/* IP header */
					i_hdr = (struct sr_ip_hdr*)(new_pck + sizeof(struct sr_ethernet_hdr));

					i_hdr->ip_v = 4;
					i_hdr->ip_hl = 5; /**이건 뭐? */
					i_hdr->ip_tos = 0;
					i_hdr->ip_len = htons(new_len - sizeof(struct sr_ethernet_hdr));
					i_hdr->ip_id = 0; /**이건 뭐? */
					i_hdr->ip_off = htons(IP_DF); /** 이건 뭐? */
					i_hdr->ip_ttl = INIT_TTL;
					i_hdr->ip_p = ip_protocol_icmp;


					i_hdr->ip_src = ifc->ip; 
					i_hdr->ip_dst =i_hdr0->ip_src;

					i_hdr->ip_sum = 0;
					i_hdr->ip_sum = cksum(i_hdr, sizeof(struct sr_ip_hdr));

					/**************** fill in code here(1) *****************/
					/* refer routing table */
					rtentry = sr_findLPMentry(sr->routing_table, i_hdr->ip_dst);
					/* routing table hit */
					if (rtentry != NULL)
					{
						/**************** fill in code here(3) *****************/

						/* Ethernet header */ 
						e_hdr = (struct sr_ethernet_hdr*) new_pck;
						e_hdr-> ether_type = htons(ethertype_ip);
						/**************** fill in code here(3) *****************/
						ifc = sr_get_interface(sr, rtentry->interface);
						memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
						
						/**next-hop 계산 자리 왜 따로 안 마련되어 (있는지) 의문이지만 일단 넣자 */
						uint32_t next_hop_ip = (rtentry->gw.s_addr != 0) ? rtentry->gw.s_addr : i_hdr->ip_dst;
						arpentry = sr_arpcache_lookup(&(sr->cache), next_hop_ip); /**여기서부터 시작 */
						if (arpentry != NULL)
						{
							/**************** fill in code here(6) *****************/
							/* Ethernet header */ 
							memcpy(e_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
							free(arpentry);
							/* send */
							sr_send_packet(sr, new_pck, new_len, rtentry->interface);
							/**(6) 더 넣어야 하는 거 없나? */
							/**************** fill in code here(6) *****************/
						}
						else
						{
							/* queue */
							arpreq = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, new_pck, new_len, rtentry->interface);
							sr_arpcache_handle_arpreq(sr, arpreq);
						}
					}

					/* done */
					free(new_pck); 
					return;
				}

				/* other types */
				else
					return;
			}
			/* with TCP or UDP */
			else if (i_hdr0->ip_p == ip_protocol_tcp || i_hdr0->ip_p == ip_protocol_udp)
			{
				/* validation */
				if (len_r + sizeof(struct sr_ip_hdr) < ICMP_DATA_SIZE)
					return;

				/* generate ICMP port unreachable packet */
				new_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
				new_pck = (uint8_t *) calloc(1, new_len);
				
				/**************** fill in code here(9) *****************/

				/* ICMP header */
				ict3_hdr = (struct sr_icmp_t3_hdr*)(new_pck + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

				/**TYPE: 3 */
				ict3_hdr->icmp_type = 3;
				ict3_hdr->icmp_code = 3;
				ict3_hdr->unused = 0;
				ict3_hdr->next_mtu = 0;

				/*payload*/
				memcpy(ict3_hdr->data, (uint8_t *) i_hdr0, sizeof(struct sr_ip_hdr) + 8);

				/*ICMP checksum*/
				ict3_hdr->icmp_sum = 0;
				ict3_hdr->icmp_sum = cksum(ict3_hdr, new_len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));
				
				/* IP header */
				i_hdr = (struct sr_ip_hdr*)(new_pck + sizeof(struct sr_ethernet_hdr));
				i_hdr->ip_v = 4;
				i_hdr->ip_hl = 5;
				i_hdr->ip_tos = 0;
				i_hdr->ip_len = htons(new_len - sizeof(struct sr_ethernet_hdr));
				i_hdr->ip_id = 0;
				i_hdr->ip_off = htons(IP_DF);
				i_hdr->ip_ttl = INIT_TTL;
				i_hdr->ip_p = ip_protocol_icmp;

				i_hdr->ip_dst = i_hdr0->ip_src;
				
				rtentry = sr_findLPMentry(sr->routing_table, i_hdr->ip_dst);
				if (rtentry != NULL) {
					e_hdr = (struct sr_ethernet_hdr*)new_pck;
					e_hdr->ether_type = htons(ethertype_ip);

					ifc = sr_get_interface(sr, rtentry->interface);
					i_hdr->ip_src = ifc->ip;
					i_hdr->ip_sum = 0;
					i_hdr->ip_sum = cksum(i_hdr, sizeof(struct sr_ip_hdr));
					memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);

					uint32_t next_hop_ip = (rtentry->gw.s_addr != 0) ? rtentry->gw.s_addr : i_hdr->ip_dst;
					arpentry = sr_arpcache_lookup(&(sr->cache), next_hop_ip);
					if (arpentry != NULL)
					{
					/* Ethernet header */
						memcpy(e_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
						free(arpentry);
						/* send */
						sr_send_packet(sr, new_pck, new_len, rtentry->interface);
					}
					else
					{
						/* queue */
						arpreq = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, new_pck, new_len, rtentry->interface);
						sr_arpcache_handle_arpreq(sr, arpreq);
					}
				}		
				/* done */
				free(new_pck); 
				/*****************************************************/
				return;
			}
			/* with others */
			else
				return;
		}
		/* destined elsewhere, forward */
		else
		{
			/* refer routing table */
			rtentry = sr_findLPMentry(sr->routing_table, i_hdr0->ip_dst);

			/* routing table hit */
			if (rtentry != NULL)
			{
				/* check TTL expiration */
				if (i_hdr0->ip_ttl == 1)
				{
					/**************** fill in code here(10) *****************/

					/* validation */
					if (len_r + sizeof(struct sr_ip_hdr) < ICMP_DATA_SIZE) 
						return;

					/* generate ICMP time exceeded packet */
					new_len = sizeof(struct sr_ethernet_hdr) +sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t11_hdr);
					new_pck = (uint8_t *) calloc(1, new_len);
					/* ICMP header */
					ict11_hdr = (struct sr_icmp_t11_hdr*)(new_pck + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

					/**TYPE: 11 */
					ict11_hdr->icmp_type = 11;
					ict11_hdr->icmp_code = 0;
					ict11_hdr->unused = 0;

					/**payload */
					memcpy(ict11_hdr->data, (uint8_t*) i_hdr0, sizeof(struct sr_ip_hdr) + 8);
			
					/**ICMP checksum */
					ict11_hdr->icmp_sum = 0;
					ict11_hdr->icmp_sum = cksum(ict11_hdr, new_len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));

					/* IP header */
					i_hdr = (struct sr_ip_hdr*)(new_pck + sizeof(struct sr_ethernet_hdr));
					i_hdr->ip_v = 4;
					i_hdr->ip_hl = 5;
					i_hdr->ip_tos = 0;
					i_hdr->ip_len = htons(new_len - sizeof(struct sr_ethernet_hdr));
					i_hdr->ip_id = 0;
					i_hdr->ip_off = htons(IP_DF);
					i_hdr->ip_ttl = INIT_TTL;
					i_hdr->ip_p = ip_protocol_icmp;

					i_hdr->ip_dst = i_hdr0->ip_src;

					rtentry = sr_findLPMentry(sr->routing_table, i_hdr->ip_dst);
					if (rtentry != NULL) {
						e_hdr = (struct sr_ethernet_hdr*)new_pck;
						e_hdr->ether_type = htons(ethertype_ip);

						ifc = sr_get_interface(sr, rtentry->interface);
						i_hdr->ip_src = ifc->ip;
						
						i_hdr->ip_sum = 0;
						i_hdr->ip_sum = cksum(i_hdr, sizeof(struct sr_ip_hdr));
						memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);

						uint32_t next_hop_ip = (rtentry->gw.s_addr != 0) ? rtentry->gw.s_addr : i_hdr->ip_dst;
						arpentry = sr_arpcache_lookup(&(sr->cache), next_hop_ip);

					/* Ethernet header */
						if (arpentry != NULL)
						{
							memcpy(e_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
							free(arpentry); 
							/* send */
							sr_send_packet(sr, new_pck, new_len, rtentry->interface);
						}
						else
						{
							/* queue */
							arpreq = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, new_pck, new_len, rtentry->interface);
							sr_arpcache_handle_arpreq(sr, arpreq);
						}
					}
					/* done */
					free(new_pck); 
					/*****************************************************/
					return;
				}
				/* TTL not expired */
				else {
					/**************** fill in code here(11) *****************/

					/* set src MAC addr */
					ifc = sr_get_interface(sr, rtentry->interface);
					memcpy(e_hdr0->ether_shost, ifc->addr, ETHER_ADDR_LEN);

					uint32_t next_hop_ip = (rtentry->gw.s_addr != 0) ? rtentry->gw.s_addr : i_hdr0->ip_dst;
					/* refer ARP table */
					arpentry = sr_arpcache_lookup(&(sr->cache), next_hop_ip);					
						/* set dst MAC addr */
						if (arpentry != NULL) {
							memcpy(e_hdr0->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
							free(arpentry);
							/* decrement TTL */
							i_hdr0->ip_ttl -= 1;
							/** recompute checksum */
							i_hdr0->ip_sum = 0;
							i_hdr0->ip_sum = cksum(i_hdr0, sizeof(struct sr_ip_hdr));
							/* forward */
							sr_send_packet(sr, packet, len, rtentry->interface);
						}
						else 
						{
						/* queue */
							/** 이 경우에는 sr_arpcache_queuereq() 안에서 decrement TTL 후 recompute? */
							arpreq = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, packet, len, rtentry->interface);
							sr_arpcache_handle_arpreq(sr, arpreq);
						}
					/*****************************************************/
					/* done */
					return;
				}
			}
			/* routing table miss */
			else
			{
				/**************** fill in code here(12) *****************/

				/* validation */
				if (len_r + sizeof(struct sr_ip_hdr) < ICMP_DATA_SIZE)
					return;

				/* generate ICMP net unreachable packet */
				new_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
				new_pck = (uint8_t *) calloc(1, new_len);

				/* ICMP header */
				ict3_hdr = (struct sr_icmp_t3_hdr*)(new_pck + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

				/**TYPE: 3 */
				ict3_hdr->icmp_type = 3;
				ict3_hdr->icmp_code = 0;
				ict3_hdr->unused = 0;
				ict3_hdr->next_mtu = 0;

				/**payload*/
				memcpy(ict3_hdr->data, (uint8_t *) i_hdr0, sizeof(struct sr_ip_hdr) + 8);
				
				/**ICMP checksum */
				ict3_hdr->icmp_sum = 0;
				ict3_hdr->icmp_sum = cksum(ict3_hdr, new_len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));

				/* IP header */
				i_hdr = (struct sr_ip_hdr*)(new_pck + sizeof(struct sr_ethernet_hdr));
				i_hdr->ip_v = 4;
				i_hdr->ip_hl = 5;
				i_hdr->ip_tos = 0;
				i_hdr->ip_len = htons(new_len - sizeof(struct sr_ethernet_hdr));
				i_hdr->ip_id = 0;
				i_hdr->ip_off = htons(IP_DF);
				i_hdr->ip_ttl = INIT_TTL;
				i_hdr->ip_p = ip_protocol_icmp;

				i_hdr->ip_dst = i_hdr0->ip_src;
				
				i_hdr->ip_sum = 0;
				i_hdr->ip_sum = cksum(i_hdr, sizeof(struct sr_ip_hdr));
				
				rtentry = sr_findLPMentry(sr->routing_table, i_hdr->ip_dst);
				if (rtentry != NULL) {
					e_hdr = (struct sr_ethernet_hdr*)new_pck;
					e_hdr->ether_type = htons(ethertype_ip);

					ifc = sr_get_interface(sr, rtentry->interface);
					i_hdr->ip_src = ifc->ip;
					i_hdr->ip_sum = 0;
					i_hdr->ip_sum = cksum(i_hdr, sizeof(struct sr_ip_hdr));
					memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);

					uint32_t next_hop_ip = (rtentry->gw.s_addr != 0) ? rtentry->gw.s_addr : i_hdr->ip_dst;
					arpentry = sr_arpcache_lookup(&(sr->cache), next_hop_ip);
					if (arpentry != NULL)
					{
					/* Ethernet header */
						memcpy(e_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
						free(arpentry);
						/* send */
						sr_send_packet(sr, new_pck, new_len, rtentry->interface);
					}
					else
					{
						/* queue */
						arpreq = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, new_pck, new_len, rtentry->interface);
						sr_arpcache_handle_arpreq(sr, arpreq);
					}
				}		
				/* done */
				free(new_pck); /***여기 free도 */
				/*****************************************************/
				return;
			}
		}
	}
	/* ARP packet arrived */
	else if (e_hdr0->ether_type == htons(ethertype_arp))
	{

		/* validation */
		if (len_r < sizeof(struct sr_arp_hdr))
			return;

		a_hdr0 = (struct sr_arp_hdr *)(((uint8_t *)e_hdr0) + sizeof(struct sr_ethernet_hdr)); /* a_hdr0 set */

		/* destined to me */
		ifc = sr_get_interface(sr, interface);
		if (a_hdr0->ar_tip == ifc->ip)
		{
			/* request code */
			if (a_hdr0->ar_op == htons(arp_op_request))
			{
				/**************** fill in code here(13) *****************/

				/* generate reply */
				new_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
				new_pck = (uint8_t *) calloc(1, new_len);

				a_hdr = (struct sr_arp_hdr*)(new_pck + sizeof(struct sr_ethernet_hdr));
				/* ARP header */
				a_hdr->ar_hrd = htons(arp_hrd_ethernet);
				a_hdr->ar_pro = htons(ethertype_ip);
				a_hdr->ar_hln = ETHER_ADDR_LEN;
				a_hdr->ar_pln = 4;
				a_hdr->ar_op = htons(arp_op_reply);

				memcpy(a_hdr->ar_sha, ifc->addr, ETHER_ADDR_LEN);
				a_hdr->ar_sip = ifc->ip;
			
				memcpy(a_hdr->ar_tha, a_hdr0->ar_sha, ETHER_ADDR_LEN);
				a_hdr->ar_tip = a_hdr0->ar_sip;

				/* Ethernet header */
				e_hdr = (struct sr_ethernet_hdr*) new_pck;
				memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
				memcpy(e_hdr->ether_dhost, a_hdr0->ar_sha, ETHER_ADDR_LEN);
				e_hdr->ether_type = htons(ethertype_arp);
				/* send */
				sr_send_packet(sr, new_pck, new_len, interface);

				/* done */
				free(new_pck);
				/*****************************************************/
				return;
			}

			/* reply code */
			else if (a_hdr0->ar_op == htons(arp_op_reply))
			{
				/**************** fill in code here(14) *****************/

				/* pass info to ARP cache */
				arpreq = sr_arpcache_insert(&(sr->cache), a_hdr0->ar_sha, a_hdr0->ar_sip);
				/* pending request exist */
				if (arpreq != NULL) {
						en_pck = arpreq->packets;
						while (en_pck != NULL) {
							e_hdr = (struct sr_ethernet_hdr *) en_pck->buf;
							/* set dst MAC addr */
							memcpy(e_hdr->ether_dhost, a_hdr0->ar_sha, ETHER_ADDR_LEN);
							/* decrement TTL except for self-generated packets */
							i_hdr = (struct sr_ip_hdr *)(en_pck->buf + sizeof(struct sr_ethernet_hdr));
							if (i_hdr->ip_ttl != INIT_TTL) {
								i_hdr->ip_ttl -= 1;
								i_hdr->ip_sum = 0;
								i_hdr->ip_sum = cksum(i_hdr, sizeof(struct sr_ip_hdr));
							}
							/* send */
							sr_send_packet(sr, en_pck->buf, en_pck->len, en_pck->iface);
							en_pck = en_pck->next;
						}
					/* done */
					sr_arpreq_destroy(&(sr->cache), arpreq);
					/*****************************************************/
					return;
				}
				/* no exist */
				else
					return;
			}

			/* other codes */
			else
				return;
		}

		/* destined to others */
		else
			return;
	}

	/* other packet arrived */
	else
		return;

} /* end sr_ForwardPacket */

struct sr_rt *sr_findLPMentry(struct sr_rt *rtable, uint32_t ip_dst)
{
	struct sr_rt *entry, *lpmentry = NULL;
	uint32_t mask, lpmmask = 0;

	ip_dst = ntohl(ip_dst);

	/* scan routing table */
	for (entry = rtable; entry != NULL; entry = entry->next)
	{
		mask = ntohl(entry->mask.s_addr);
		/* longest match so far */
		if ((ip_dst & mask) == (ntohl(entry->dest.s_addr) & mask) && mask > lpmmask)
		{
			lpmentry = entry;
			lpmmask = mask;
		}
	}

	return lpmentry;
}
