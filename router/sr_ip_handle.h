#ifndef SR_IP_HANDLE_H
#define SR_IP_HANDLE_H

#include <stdint.h>



/*general function to check if IP packet needs to be forwared or it's destined for us.*/
void sr_ip_handle(struct sr_instance *sr, uint8_t *packet, int len, struct sr_if *iface);
/*function to handle packets destined for one of our interfaces.*/
void sr_ip_router_handle(struct sr_instance *sr, uint8_t *packet, int len, struct sr_if *iface);
/*function to handle packets that needs forwarding*/
void sr_ip_forward_handle(struct sr_instance *sr, uint8_t *packetl, int len, struct sr_if *iface);


#endif