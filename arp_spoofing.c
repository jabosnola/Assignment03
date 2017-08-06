#incldue "arp_spoofing.h"

void arp_spoofing(pcap_t *handle, struct network_pack *net1, struct network_pack *net2, struct network_pack *net3)
{
	struct pcap_pkthdr header;
	const u_char *packet;
	int state = 0;
	struct ether_header *ether;
	struct ether_arp *arp;
	struct ip *ipv4;

	while(1)
	{
		state = pcap_next_ex(handle, &header, &packet);
		if (state < 1)
			continue;
		ether = (struct ether_header *)packet;

		//ARP PACKET- > RE-INFECTION//
		if(ntohs(ether->ether_type) == ETHERTYPE_ARP)
		{
			arp = (struct ether_arp *)(packet + 14);

			//CHECK SENDER'S ARP REQUEST//


			//CHECK TARGET'S ARP REQUEST//
		}
		//IP PACKET -> RELAY//
		else if(ntohs(ether->ether_type) == ETHERTYPE_IP)
		{
			ipv4 = (struct ip *)(packet + 14);

			//RELAY FROM ATTACKER TO TARGET//


			//RELAY FROM ATTACKER TO SENDER//
		}
	}
	

}