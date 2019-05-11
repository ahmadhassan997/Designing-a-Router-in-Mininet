#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "sr_helper.h"
#include "sr_utils.h"
#include "sr_arp_handle.h"
#include "sr_protocol.h"
#include "sr_if.h"
#include "sr_router.h"
#include "sr_arpcache.h"

void sr_arp_handle(struct sr_instance *sr, uint8_t *packet, int len, struct sr_if *iface)
{
	/*check for minimum length of the packet using sanity check*/
	if(arp_len_sanity_check(len))
	{
		/*Process the packet if sanity check passed.*/
		Debug("ARP packet received!\n");
		sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet);
		sr_arp_hdr_t *arp_hdr = get_arp_hdr(packet);

		/*check if it's an ARP reply or request.*/
		if(ntohs(arp_hdr->ar_op)==arp_op_request)
		{
			/*define a new function to process ARP requests*/
			sr_arp_req_handle(sr,eth_hdr,arp_hdr,iface);
		}
		else if(ntohs(arp_hdr->ar_op)==arp_op_reply)
		{
			/*make a new function to handle ARP replies*/
			sr_arp_rep_handle(sr,arp_hdr,iface);
		}
		else
		{
			/*if it's neither a request nor a reply.*/
			Debug("ARP processing failed.\n");
			return;

		}
	}
	else
	{
		/*return if sanity check failed.*/
		Debug("ARP Sanity Check Failed. Packet Dropped!!\n");
		return;
	}
}


void sr_arp_req_handle(struct sr_instance *sr, sr_ethernet_hdr_t *eth_hdr, sr_arp_hdr_t *arp_hdr, struct sr_if *iface)
{
	/*Ok so based on the pseudocode defiend in sr_arpcache.h if we get a 
	request, it might be for us or it may be for someone else but we need
	to cache it regardless of its tip.
	If it's for me, I need to respond to it with an ARP reply using the
	sr_arp_rep_handle.*/

	/* cache it */
	sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

	/* if it was for me send the ARP reply*/
	if(arp_hdr->ar_tip==iface->ip)
	{
		Debug("Sending reply to ARP request\n");
		sr_send_arp_rep(sr,eth_hdr,arp_hdr,iface);	/* function defined in
		 sr_helper.h to send ARP replies.l*/
	}
	

}


void sr_arp_rep_handle(struct sr_instance *sr, sr_arp_hdr_t *arp_hdr, struct sr_if *iface)
{
	/*add code to this function based on the pseudocode defined in 
	sr_arpcache.h header.*/
	/* First check if we're the target for this arp reply.
	/// Then, cache the reply to insert this mapping in our ARP cache.
	//// For this particular ARP reply, send all the waiting packets
	///// present in the request queue.
	////// Now destroy this request as it has been served.*/

	/*We need to get exclusive access to the cache as it's been called again
	and again.*/

	/*check dest of the reply(as we sent the request and we're getting this reply)*/
	if(iface->ip==arp_hdr->ar_tip)
	{
		Debug("ARP reply received at %s",iface->name);

		/*use lock to get exclusive access to cache.*/

		pthread_mutex_lock(&sr->cache.lock);

		/* Store the ip->mac mapping that we got in reply in the ARP cache.*/

		struct sr_arpreq *rep_to_req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

		/* Using request queue send all the packets that were waiting on this
		 ARP reply*/

		if(rep_to_req != NULL)
		{
			/* extract packets fromm the list and send them turn by turn.*/
			struct sr_packet *packets_waiting = rep_to_req->packets;
			while(packets_waiting)
			{
				Debug("Sending waiting packets for ARP reply\n");
				/*pass this to a new function that will odify the ethernet header
				and send the packet using sr_send_packet after computing checksum*/
				sr_fwd_pkt(sr, packets_waiting->buf, packets_waiting->len, arp_hdr->ar_sha, iface);


				packets_waiting = packets_waiting->next;
			} 
		}

		/*release the lock*/

		pthread_mutex_unlock(&sr->cache.lock);

	}
	else
	{
		return;
	}
}