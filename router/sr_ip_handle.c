#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "sr_helper.h"
#include "sr_utils.h"
#include "sr_ip_handle.h"
#include "sr_protocol.h"
#include "sr_if.h"
#include "sr_router.h"
#include "sr_arpcache.h"


void sr_ip_handle(struct sr_instance *sr, uint8_t *packet, int len, struct sr_if *iface)
{
	Debug("Getting IP packet\n");
	/*If we receive a packet it's either destined for us or we need to forward it 
	to the next hop. If it's for me I pass it to the sr_ip_router_handle function
	to handle the ip packets destined for me. If it's for someone else, we do the 
	forwarding after sanity checks.*/
	/*Check TTL too before calling the forwarding function.*/
	/**********************************************************************/
	/*check for minimum packet length.*/
	if(!ip_len_sanity_check(len))
	{
		Debug("IP sanity check failed! Packet dropped.\n");
		return;
	}
	/*wrong checksum*/
	sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);
	if(!checksum_ip_isok(ip_hdr))
	{
		Debug("checksum IP is not same! Packet dropped.\n");
		return;
	}

	/*check if the packet is detined for one of our interfaces.*/
	struct sr_if *my_interfaces = sr->if_list;
	while(my_interfaces)
	{
		/*check if the packet IP destination id same as the IP of one of
		our interfaces.*/
		if(ip_hdr->ip_dst == my_interfaces->ip)
		{
			Debug("Packet for our router\n"); /*may print interface as well*/
			sr_ip_router_handle(sr,packet,len,my_interfaces);
			return;
		}
		my_interfaces = my_interfaces->next;
	}

	/*if the while loop closes without finding the inetrface, forward the 
	packet.*/
	Debug("forwarding packet\n");
	/*check if TTL becomes zero.*/
	if(--ip_hdr->ip_ttl == 0)
	{
		Debug("TTL 0, packet dropped sending TTL expired ICMP\n");
		/* if ttl is zero send icmp t3 error message. */
		sr_send_icmp_t3(sr, packet, icmp_protocol_type_time_exceed, icmp_protocol_code_ttl_expired, iface);
		return;
	}

	/*If TTL != 0 forward the packet using the forwarding logic defined in
	sr_ip_forward_handle.*/

	sr_ip_forward_handle(sr,packet,len,iface);



}

void sr_ip_router_handle(struct sr_instance *sr, uint8_t *packet, int len, struct sr_if *iface)
{
	/*We enter this function if the target ip is one of our interfaces.*/
	Debug("IP packet received.\n");
	/*Now we need to check the protocol type of our IP packet. If it's
	UDP/TCP, send ICMP port unreacable error. If it's an ICMP, do checksum
	and sanity checks and if it's an ICMP request send ICMP reply.*/

	/* get IP header*/
	sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);

	/* now check if it's TCP, UDP or ICMP packet.*/

	if(ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp)
	{
		Debug("TCP/UDP packet received. Sending port unreacable message.\n");
		/* ICMp port unreachable */
		sr_send_icmp_t3(sr, packet, icmp_protocol_type_dest_unreach, icmp_protocol_code_port_unreach, iface);
		return;		
	}
	else if(ip_hdr->ip_p == ip_protocol_icmp)
	{
		/* get icmp header to send the reply to echo request after verifying
		 checksum and doing sanity check.*/
		sr_icmp_hdr_t *icmp_hdr = get_icmp_hdr(packet);
		/*check for minimum packet length.*/
		if(!icmp_len_sanity_check(len))
		{
			Debug("ICMP sanity check failed! Packet dropped.\n");
			return;
		}
		/*wrong checksum*/
		if(!checksum_icmp_isok(ip_hdr->ip_len, icmp_hdr))
		{
			Debug("checksum ICMP is not same! Packet dropped.\n");
			return;
		}

		/*Now send ICMP echo reply.*/
		if(icmp_hdr->icmp_type == icmp_protocol_type_echo_req && icmp_hdr->icmp_code == icmp_protocol_code_empty)
		{
			sr_send_icmp(sr, icmp_protocol_type_echo_rep, icmp_protocol_type_echo_rep, packet, len, iface);
		}
		return;
	}
	else
	{
		Debug("Can't find matching protocol for IP packet.\n");
		return;
	}

}

void sr_ip_forward_handle(struct sr_instance *sr, uint8_t *packet, int len, struct sr_if *iface)
{
	/*To forward this packet , first check if we have a outgoing interface
	to send this packet. If not, send an ICMP net unreacable message. If the
	interface is found find the next hop mac address from arp cache and forward
	the packet. If there's no entry in the arpcache, create an ARP request and
	pass it to sr_arp_req_handle function.*/

	/*find the outgoing interface*/
	struct sr_if *iface_out = sr_if_dest(sr, get_ip_hdr(packet)->ip_dst);
	/* if the interface was found send the packet otherwise send ICMP
	 error message */
	if(iface_out)
	{
		Debug("interface found for this packet.\n");
		sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);
		/* lookup for the corresponding ip->mac mapping in arp cache*/
		struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);

		/* if the ARP entry was found forward the packet*/

		if(arp_entry)
		{
			Debug("ip->mac mapping found\n");
			/*forward the packet after modifying it(use sr_fwd_pkt that we defined
			in sr_helper.h file)*/
			sr_fwd_pkt(sr, packet, len, arp_entry->mac, iface_out);

			/* free this entry as we were asked to do so in pseudocode*/
			free(arp_entry);
			return;
		}
		else
		{
			/* if arp_entry not found generate a new ARP request and 
			 let the ARP protocol handle everything about this 
			 ARP request.*/
			Debug("ip->mac mapping not found. Initiating ARP protocol.\n");
			/* make ARP request*/
			struct sr_arpreq *arp_req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, iface_out->name);
			/* pass it to arp protocol to handle the request.*/
			sr_arpcache_handle_req(sr,arp_req);
		}
	}
	else
	{
		Debug("No interface for this packet.\n");
		/* send error message using the same interface at which we received the packet on.*/
		sr_send_icmp_t3(sr, packet, icmp_protocol_type_dest_unreach, icmp_protocol_code_net_unreach, iface);
	}

}