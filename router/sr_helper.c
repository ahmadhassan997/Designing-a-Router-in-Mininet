#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "sr_helper.h"
#include "sr_utils.h"
#include "sr_protocol.h"
#include "sr_if.h"
#include "sr_router.h"
#include "sr_arpcache.h"
#include "sr_rt.h"



/**************************************************************/
/* Some packets need special handling to send them over to the network
 like in case of ICMP echo requests/replies or ARP replies.*/

/*Ok the task is to send ICMP packet reply while data section isn't added
to it. */
/*This function can be called multiple times to produce ICMP messages with any type/code.*/
int sr_send_icmp(struct sr_instance *sr, uint8_t type, uint8_t code, uint8_t *packet, int len, struct sr_if *iface)
{
	/* extract ethernet,ip and icmp headers to work with.*/
	sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet);

	sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);
	/* the interface that we got in parameters is the interface that we 
	 received this packet from so we have to find the out interface.*/

	struct sr_if *iface_out = sr_if_dest(sr,ip_hdr->ip_src);


	/* change the source/dest fields */
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);/*As we
	 need to send packet towards the source address*/
	memcpy(eth_hdr->ether_shost, iface_out->addr, ETHER_ADDR_LEN);

	
	sr_icmp_hdr_t *icmp_hdr = get_icmp_hdr(packet);
	/*change the source/dest for ip header*/
	uint32_t temp = ip_hdr->ip_src;
	ip_hdr->ip_src = iface->ip;
	ip_hdr->ip_dst = temp;

/* now add the icmp types and codes.*/

	icmp_hdr->icmp_type = type;
	icmp_hdr->icmp_code = code;

/* compute checksum*/

	icmp_hdr->icmp_sum = 0;
	icmp_hdr->icmp_sum = cksum(icmp_hdr,sizeof(sr_icmp_hdr_t));

	/*send the packet using the same default function that's defined in
	 router.h to send packets.*/

	int check = sr_send_packet(sr,packet,len,iface_out->name);
	return check;

	
}

/* for this function I couldn't modify the packet so I create a 
 new packet and work with it.*/
int sr_send_icmp_t3(struct sr_instance *sr, uint8_t *packet_rec, uint8_t type, uint8_t code, struct sr_if *iface)
{

	/* so we need to make a new packet whose length would be the sum of 
	 ethernet, ip and icmp hdr lengths.*/

	uint8_t *packet = (uint8_t *)malloc(sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

	/* now we need to make sure that our packet contains all zeros to start with
	 so we can use bzero function to copy zeros in our packet.*/

	bzero(packet, sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));


	/* extract ethernet,ip and icmp headers to work with(for new packet).*/
	sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet);
	sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);
	sr_icmp_t3_hdr_t *icmp_hdr = get_icmp_t3_hdr(packet);

	/* extract ethernet,ip and icmp headers to work with(for origninal 
	 sender packet) that is our receiver.*/

	sr_ethernet_hdr_t *eth_hdr_rec = get_eth_hdr(packet_rec);
	sr_ip_hdr_t *ip_hdr_rec = get_ip_hdr(packet_rec);
	/*sr_icmp_hdr_t *icmp_hdr_rec = get_icmp_hdr(packet_rec);*/

	/* now find the outgoing interface just as we did before.*/

	struct sr_if *iface_out = sr_if_dest(sr, ip_hdr_rec->ip_src);

	/**Now we can construct ethernet, IP and ICMP header**/

	/* Ethernet Header*/
	memcpy(eth_hdr->ether_dhost, eth_hdr_rec->ether_shost, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, iface_out->addr, ETHER_ADDR_LEN);
	eth_hdr->ether_type = htons(ethertype_ip);

	/* IP Header*/
	/*modify these fields according to the packet who produced the error.*/

	ip_hdr->ip_hl = ip_hdr_rec->ip_hl;
	ip_hdr->ip_v = ip_hdr_rec->ip_v;
	ip_hdr->ip_tos = ip_hdr_rec->ip_tos;
	ip_hdr->ip_id = 0;
	ip_hdr->ip_off = htons(IP_DF);
	ip_hdr->ip_ttl = INIT_TTL;
	ip_hdr->ip_p = ip_protocol_icmp;
	ip_hdr->ip_src = iface->ip;
	ip_hdr->ip_dst = ip_hdr_rec->ip_src;
	ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

	/*ICMP header*/

	icmp_hdr->icmp_type = type;
	icmp_hdr->icmp_code = code;
	/* place first few bytes in the packet. defined in RFC*/ 
	memcpy(icmp_hdr->data, ip_hdr_rec, ICMP_DATA_SIZE);
	icmp_hdr->icmp_sum = 0;
	icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

	/**Now send the packet using same default function*/

	int check = sr_send_packet(sr,packet,sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) , iface_out->name);
	return check;


}

int sr_send_arp_rep(struct sr_instance *sr, sr_ethernet_hdr_t *eth_hdr_rec,sr_arp_hdr_t *arp_hdr_rec, struct sr_if *iface)
{
	/* it's better to define the size of packet instead of writing it 
	 again and again like in te previous function :p*/
	int packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);

	/* make a new packet and fill it with zeros.*/
	uint8_t *packet = (uint8_t *)malloc(packet_size);
	bzero(packet,packet_size);

	/*extract headers(of new packet).*/
	sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet);
	sr_arp_hdr_t *arp_hdr = get_arp_hdr(packet);

	/*Now we need to fill all the fields of ethernet and ARP headers*/

	/* Ethernet Header*/

	memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_dhost, eth_hdr_rec->ether_shost, ETHER_ADDR_LEN);
	eth_hdr->ether_type = ntohs(ethertype_arp);

	/* ARP Header*/

	arp_hdr->ar_hrd = arp_hdr_rec->ar_hrd;
	arp_hdr->ar_pro = arp_hdr_rec->ar_pro;
	arp_hdr->ar_hln = arp_hdr_rec->ar_hln;
	arp_hdr->ar_pln = arp_hdr_rec->ar_pln;
	arp_hdr->ar_op = htons(arp_op_reply);
	arp_hdr->ar_sip = iface->ip;
	arp_hdr->ar_tip = arp_hdr_rec->ar_sip;
	memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
	memcpy(arp_hdr->ar_tha, arp_hdr_rec->ar_sha, ETHER_ADDR_LEN);



	int check = sr_send_packet(sr, packet, packet_size, iface->name);

}

/*send ARP reuest kepping in mind the destination MAC address would be 0xff*/
/*ARP requests use the broadcast address to find the MAC address of target IP.*/
/*Again we create a new packet using the malloc function.*/
int sr_send_arp_req(struct sr_instance *sr, uint32_t dest_ip)
{

	/* Now figure out the outgoing interface*/

	struct sr_if *iface = sr_if_dest(sr, dest_ip);


	int packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);

	/* make a new packet and fill it with zeros.*/
	uint8_t *packet = (uint8_t *)malloc(packet_size);
	bzero(packet,packet_size);


	sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet);
	sr_arp_hdr_t *arp_hdr = get_arp_hdr(packet);

	/* Add ethernet and ARP hedaers */

	/* Ethernet Header*/

	memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);/*outgoing interface
	i.e. the source addr for this packet*/
	memset(eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN); /*dest MAC addr 0xff for
	 ARP requests as we need to find this MAC addr.*/

	eth_hdr->ether_type = htons(ethertype_arp);

	/* ARP Header */

	arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
	arp_hdr->ar_pro = htons(ethertype_ip);
	arp_hdr->ar_hln = ETHER_ADDR_LEN;
	arp_hdr->ar_pln = 4;
	arp_hdr->ar_op  = htons(arp_op_request);
	arp_hdr->ar_sip = iface->ip;
	arp_hdr->ar_tip = dest_ip;
	memset(arp_hdr->ar_tha, 0xff, ETHER_ADDR_LEN);
	memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);

	int check = sr_send_packet(sr, packet, packet_size, iface->name);
	return check;




}

/********************************************************************/
/*These functions are among the most used chunks of code used in my assignment and all they
do is to point to differnt headers inside the packet. */
sr_icmp_t3_hdr_t *get_icmp_t3_hdr(uint8_t *packet)
{
	/*icmpt3 is beneath the IP and ofcourse ethernet header.*/
	return (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
}

sr_icmp_hdr_t *get_icmp_hdr(uint8_t *packet)
{
	/*icmp is beneath the IP and ofcourse ethernet header.*/
	return (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
}

sr_arp_hdr_t *get_arp_hdr(uint8_t *packet)
{
	/*arp header follows the ethernet header.*/
	return (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
}

sr_ethernet_hdr_t *get_eth_hdr(uint8_t *packet)
{

	return (sr_ethernet_hdr_t *)packet;
}

sr_ip_hdr_t *get_ip_hdr(uint8_t *packet)
{
	/*IP header follows the ethernet header.*/
	return (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)); 
}

/*****************************************************************/
/* To get next hop interface*/
/*evry time we need to get the outgoing interface of our 
packet, we use this function. It takes the instance and dest IP as input
and reurns us the outgoing link interface to reach to that dest using the 
forwarding table.*/
struct sr_if* sr_if_dest(struct sr_instance *sr, uint32_t dest)
{
	struct sr_rt* temp_node  = sr->routing_table; /*defined in sr_rt.h and 
	 captures information about node entries in the routing table.*/
	/*routing table entries have subnet, mask fields, destination fields*/
	while(temp_node)
	{
		uint32_t temp = temp_node->mask.s_addr & dest;
		if(temp_node->dest.s_addr == temp)
		{
			return sr_get_interface(sr, temp_node->interface); /*defined in 
			sr_if.h to get the interface to send this packet on.*/
		}
		temp_node = temp_node->next;
	}

	/*if not found in the routing table return NULL*/
	return NULL;

}


/*****************************************************************************/
/* simply forward packets one hop by changing the dest/src MAC address and after compting 
the checksum for these packets.*/
void sr_fwd_pkt(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t* mac_dest, struct sr_if *iface)
{
	sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);
	sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet);
	/* memcpy(s,d,l) copies l bytes from d to s*/
	/* copy MAC address that we've figured out in the destination addr
	 of this packet and addr of outgoing interface in the source addr.*/
	memcpy(eth_hdr->ether_dhost, mac_dest, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

	/*i forgot checking the checksum again that caused me a lot of trouble 
	so we need to calculate the checksum of header after we added new
	 host and destination addresses.*/
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = cksum((const void *)ip_hdr, sizeof(sr_ip_hdr_t));

	sr_send_packet(sr,packet,len,iface->name); /*defiend in router.h to 
	 send packets.*/

}