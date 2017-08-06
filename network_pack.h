#include <netinet/in.h>
#include <netinet/ether.h>

struct network_pack
{
	struct in_addr ip;
	struct ether_addr mac;
};