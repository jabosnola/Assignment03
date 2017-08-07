#include <netinet/ip.h>
#include "send_arp.h"

void arp_spoofing(pcap_t *handle, struct network_pack *attacker, struct network_pack *sender, struct network_pack *target);