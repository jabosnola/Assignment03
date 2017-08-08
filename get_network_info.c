#include <stdio.h>
#include <string.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "get_network_info.h"

void get_network_info(char *dev, struct network_pack *network){
	char cmd[200];
	char imm[sizeof(struct in_addr)*4];
	char imm2[sizeof(struct ether_addr)*3];
	FILE *fp;
	int s;
	//IP address//
	sprintf(cmd, "ifconfig | grep -A 1 '%s' | grep 'inet addr' | awk '{print $2}' | awk -F':' '{print $2}'",dev);
	fp = popen(cmd, "r");
	fgets(imm, sizeof(imm), fp);
	pclose(fp);
	imm[strlen(imm)-1] = 0;
	printf("Attacker's IP: %s\n", imm);
	s = inet_pton(AF_INET, imm, &network->ip);
	if(s == 0)
	{
		printf("SRC does not contain a valid network address\n");
		return;
	}
	else if(s == -1)
	{
		printf("AF does not contain a valid address family\n");
		return;
	}
	//MAC address//
	sprintf(cmd, "ifconfig | grep '%s' | awk '{print$5}'",dev);
	fp = popen(cmd, "r");
	fgets(imm2, sizeof(imm2), fp);
	pclose(fp);
	printf("Attacker's MAC: %s\n", imm2);
	ether_aton_r(imm2, &network->mac);
}
