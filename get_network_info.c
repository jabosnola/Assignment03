#include <stdio.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "get_network_info.h"

void get_network_info(char *dev, struct network_pack *network){
	char cmd[200], imm[sizeof(struct in_addr)*4];
	char imm2[50];
	FILE *fp;
	//IP address//
	sprintf(cmd, "ifconfig | grep -A 1 '%s' | grep 'inet addr' | awk '{print $2}' | awk -F':' '{print $2}'",dev);
	fp = popen(cmd, "r");
	fgets(imm, sizeof(imm), fp);
	pclose(fp);
	printf("Attacker's IP: %s\n", imm);
	inet_pton(AF_INET, imm, &network->ip);
	//MAC address//
	sprintf(cmd, "ifconfig | grep '%s' | awk '{print$5}'",dev);
	fp = popen(cmd, "r");
	fgets(imm2, sizeof(imm2), fp);
	pclose(fp);
	printf("Attacker's MAC: %s\n", imm2);
	ether_aton_r(imm2, &network->mac);
}
