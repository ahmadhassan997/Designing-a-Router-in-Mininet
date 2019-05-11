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


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_arp_handle.h"
#include "sr_ip_handle.h"
#include "sr_helper.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
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

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */



  /* First we need to collect information about the incoming packet i.e. the 
  the incoming interface of our received packet and type of packet.
  We'll handle these packets based on their type(IP or ARP)*/

  struct sr_if *iface = sr_get_interface(sr , interface); /*Used from 
  <sr_if.h> to get interface on which the packet was received.*/

  uint16_t pkt_type = ethertype(packet); /*To figure out the type of packet
  so we can handle it appropriately.*/

/******************************************************/
/* Now pass the function parameters to appropriate handler files and let
 them do their work.*/

  if(pkt_type==ethertype_arp)
  {
  	sr_arp_handle(sr,packet,len,iface); /* new header for ARP packet handling.*/
  }
  else if(pkt_type==ethertype_ip)
  {
  	sr_ip_handle(sr,packet,len,iface); /* new header for IP packet handling.*/
  }
  else
  {
  	printf("Couldn't figure out packet type.\n"); /* drop the packet.*/
  	return;
  }


}/* end sr_ForwardPacket */

