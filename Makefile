all: run

run: get_network_info.o arp_request.o send_arp.o main.o
	gcc -o run get_network_info.o arp_request.o send_arp.o main.o -lpcap -W -Wall

get_network_info.o: get_network_info.c get_network_info.h network_pack.h
	gcc -c -o get_network_info.o get_network_info.c -W -Wall

arp_request.o: arp_request.c arp_request.h
	gcc -c -o arp_request.o arp_request.c -lpcap -W -Wall

send_arp.o: send_arp.c send_arp.h
	gcc -c -o send_arp.o send_arp.c -lpcap -W -Wall

main.o: main.c get_network_info.h network_pack.h send_arp.h
	gcc -c -o main.o main.c -lpcap -W -Wall

clean:
	rm *.o run