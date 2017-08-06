#include "arp_request.h"

void arp_request(pcap_t *handle, struct network_pack *net1, struct network_pack *net2)
{
	struct ether_header ether, *ether_reply;
	struct ether_addr dst, src;
	struct ether_arp arp, *arp_reply;
	u_char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
	const u_char *reply;
	int status = 0;
	struct pcap_pkthdr *header;

	ether.ether_type = htons(ETHERTYPE_ARP); 

	ether_aton_r("ff:ff:ff:ff:ff:ff", &dst);

	memcpy(ether.ether_dhost, &dst.ether_addr_octet, ETHER_ADDR_LEN);

	memcpy(ether.ether_shost, net1->mac.ether_addr_octet, ETHER_ADDR_LEN);

	arp.arp_hrd = htons(ARPHRD_ETHER);
	arp.arp_pro = htons(ETHERTYPE_IP);
	arp.arp_hln = ETHER_ADDR_LEN;
	arp.arp_pln = sizeof(struct in_addr);
	arp.arp_op = htons(ARPOP_REQUEST);
	memcpy(&arp.arp_sha, &net1->mac, ETHER_ADDR_LEN);

	memcpy(&arp.arp_spa, &net1->ip, sizeof(struct in_addr));
	ether_aton_r("00:00:00:00:00:00", &src);
	memcpy(&arp.arp_tha, &src, ETHER_ADDR_LEN);
	memcpy(&arp.arp_tpa, &net2->ip, sizeof(struct in_addr));

	memcpy(packet, &ether, sizeof(struct ether_header));
	memcpy(packet+sizeof(struct ether_header), &arp, sizeof(struct ether_arp));

	while(1) 
	{
    	if(pcap_sendpacket(handle, packet, sizeof(packet)) == -1)
    	{
    		printf("packet send error\n");
    		continue;
    	}
    	status = pcap_next_ex(handle, &header, &reply);

    	if(status < 1)
    		continue;

    	ether_reply = (struct ether_header*)reply;
			
		if(ntohs(ether_reply->ether_type) != ETHERTYPE_ARP)
			continue;

		arp_reply = (struct ether_arp *)(reply+14);
		
		if(ntohs(arp_reply->arp_op) != ARPOP_REPLY)
			continue;

		if(memcmp(&net2->ip, arp_reply->arp_spa, sizeof(struct in_addr)) !=0)
			continue;

		if(memcmp(&net1->ip, arp_reply->arp_tpa, sizeof(struct in_addr)) !=0)
			continue;
		
		memcpy(net2->mac.ether_addr_octet, arp_reply->arp_sha, ETHER_ADDR_LEN);
		
		break;
    }
}