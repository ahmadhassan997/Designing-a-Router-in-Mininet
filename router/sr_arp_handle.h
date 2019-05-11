#ifndef SR_ARP_HANDLE_H
#define SR_ARP_HANDLE_H

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


/*function to handle arp packets after we discover that a packet is arp*/
/* called from sr_router.c file.*/
void sr_arp_handle(struct sr_instance *sr, uint8_t *pkt, int len, struct sr_if *iface);

/*function to handle the arp requests and process them using other helper functions*/
void sr_arp_req_handle(struct sr_instance *sr, sr_ethernet_hdr_t *eth_hdr, sr_arp_hdr_t *arp_hdr, struct sr_if *iface);

/*Function to process ARP replies and store their results in ARP cache and 
 forward the packets on request queues*/
void sr_arp_rep_handle(struct sr_instance *sr, sr_arp_hdr_t *arp_hdr, struct sr_if *iface);


#endif