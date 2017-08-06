#include <netinet/if_ether.h>

#include "arp_request.h"

void send_arp(pcap_t *handle, struct network_pack *net1, struct network_pack *net2, struct network_pack *net3);