/*validation*/
checksum = ic_hdr0->icmp_sum;
ic_hdr0->icmp_sum = 0;
if (checksum != cksum(ic_hdr0, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr)))
    return;
ic_hdr0->icmp_sum = checksum;

/*ICMP header*/
ict0_hdr = (struct sr_icmp_t0_hdr*)(new_pck + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

/*TYPE: 0 */
ict0_hdr->icmp_type = 0;
ict0_hdr->icmp_code = 0;

/*payload
1) len - sizeof(struct sr_ethernet_hdr) 쓰면 안 되는 이유 
1) ip_total_len에 ntohs 적용하는 거 맞는지 */
memcpy(&ict0_hdr->icmp_identifier, ((uint8_t*)ic_hdr0 + sizeof(struct sr_icmp_hdr)), len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr) - sizeof(struct sr_icmp_hdr));

/*ICMP 헤더 체크섬 계산*/
ict0_hdr->icmp_sum = 0;
ict0_hdr->icmp_sum = cksum(ict0_hdr, new_len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));

/*IP header*/
i_hdr = (struct sr_ip_hdr*)(new_pck + sizeof(struct sr_ethernet_hdr));

i_hdr->ip_v = 4;
i_hdr->ip_hl = 5;
i_hdr->ip_tos = 0;
i_hdr->ip_len = htons(new_len - sizeof(struct sr_ethernet_hdr));
i_hdr->ip_id = 0;
i_hdr->ip_off = htons(IP_DF);
i_hdr->ip_ttl = 64;
i_hdr->ip_p = ip_protocol_icmp;

i_hdr->ip_src = ifc->ip;
i_hdr->ip_dst = i_hdr0->ip_src;

i_hdr->ip_sum = 0;
i_hdr->ip_sum = cksum(i_hdr, sizeof(struct sr_ip_hdr));

rtentry = sr_findLPMentry(sr->routing_table, i_hdr->ip_dst);
if (rtentry != NULL)
{
    e_hdr = (struct sr_ethernet_hdr*) new_pck;
    e_hdr-> ether_type = htons(ethertype_ip);

    /*ip_dst로 갈 때 거쳐야 하는 interface src MAC ADDRESS 넣는 부분?*/
    ifc = sr_get_interface(sr, rtentry->interface);
    memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);

    /*이 부분은 dst MAC ADDRESS 찾는 부분? 게이트웨이-외부네트워크, 그 게이트웨이의 ip 없으면 내부, ip_dst 그대로 맞나?*/
    uint32_t next_hop_ip = (rtentry->gw.s_addr != 0) ? rtentry->gw.s_addr : i_hdr->ip_dst;
    arpentry = sr_arpcache_lookup(&(sr->cache), next_hop_ip); // lookup for dst MAC address
    if (arpentry != NULL)
    {
        /*Ethernet header*/
        memcpy(e_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
        free(arpentry);
        /*send*/
        sr_send_packet(sr, new_pck, new_len, rtentry->interface);
    }
    else 
    {
        /*queue*/
        arpreq = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, new_pck, new_len, rtentry->interface);
        sr_arpcache_handle_arpreq(sr, arpreq);
    }
}

/*** type 3, code 3 */
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

				i_hdr->ip_src = ifc->ip;
				i_hdr->ip_dst = i_hdr0->ip_src;
				
				i_hdr->ip_sum = 0;
				i_hdr->ip_sum = cksum(i_hdr, sizeof(struct sr_ip_hdr));
				
				rtentry = sr_findLPMentry(sr->routing_table, i_hdr->ip_dst);
				if (rtentry != NULL) {
					e_hdr = (struct sr_ethernet_hdr*)new_pck;
					e_hdr->ether_type = htons(ethertype_ip);

					ifc = sr_get_interface(sr, rtentry->interface);
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
				free(new_pck) // *** 여기 free도 다시 생각해보기
				/*****************************************************/
				return;
			}

/***** 나중에 고민해볼 부분 *****/
/*payload
1) len - sizeof(struct sr_ethernet_hdr) 쓰면 안 되는 이유 
1) ip_total_len에 ntohs 적용하는 거 맞는지 */
uint16_t ip_total_len = ntohs(i_hdr0->ip_len);
uint16_t icmp_payload_len = ip_total_len - sizeof(struct sr_ip_hdr) - sizeof(struct sr_icmp_hdr);
memcpy(ict0_hdr->data, ((uint8_t*)ic_hdr0 + sizeof(struct sr_icmp_hdr)), icmp_payload_len);

/*ICMP 헤더 체크섬 계산*/
ict0_hdr->icmp_sum = 0;
ict0_hdr->icmp_sum = cksum(ict0_hdr, new_len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));