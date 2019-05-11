#ifndef SR_HELPER_H
#define SR_HELPER_H

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
#include "sr_arp_handle.h"
#include "sr_ip_handle.h"



/*these functions are used to create new packets of diffret types e.g. when we need to send
ICMP req/rep or ICMPt3 error msgs or ARP req/rep.*/

int sr_send_icmp(struct sr_instance *sr, uint8_t type, uint8_t code, uint8_t *packet, int len, struct sr_if *iface);

int sr_send_icmp_t3(struct sr_instance *sr, uint8_t *receiver, uint8_t type, uint8_t code, struct sr_if *iface);

int sr_send_arp_rep(struct sr_instance *sr, sr_ethernet_hdr_t *req_eth_hdr,sr_arp_hdr_t *req_arp_hdr, struct sr_if *iface);

int sr_send_arp_req(struct sr_instance *sr, uint32_t tip);



/*Methods to get headers from packets*/
/*Used in other function that I made to forward packets and send 
ICMP and ARP replies.*/
sr_icmp_t3_hdr_t *get_icmp_t3_hdr(uint8_t *packet);
sr_icmp_hdr_t *get_icmp_hdr(uint8_t *packet);
sr_arp_hdr_t *get_arp_hdr(uint8_t *packet);
sr_ethernet_hdr_t *get_eth_hdr(uint8_t *packet);
sr_ip_hdr_t *get_ip_hdr(uint8_t *packet);


/*To get next hop interface*/
struct sr_if* sr_if_dest(struct sr_instance *sr, uint32_t dest);

/*Forward packet on hop.*/

void sr_fwd_pkt(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t* mac_dest, struct sr_if *iface);


#endif