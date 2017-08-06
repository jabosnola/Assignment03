#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <pcap.h>
#include "get_network_info.h"

void arp_request(pcap_t *handle, struct network_pack *net1, struct network_pack *net2);