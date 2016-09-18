#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/in_systm.h>

#define BUFFSIZE 1518
#define ETH_TYPE_INDEX 12
#define ARP_TYPE_INDEX 21
#define ARP_REQUEST 1
#define ARP_REPLY 2

unsigned char buffer[BUFFSIZE];

int arp_request_count = 0;
int arp_request_percentage = 50;
int arp_reply_count = 0;
int arp_reply_percentage = 50;

int sockd;
int on;
struct ifreq ifr;

bool is_ipv4(char *buffer) {
	return buffer[0] == 8 && buffer[1] == 0;
}

bool is_arp(char *buffer) {
	return buffer[0] == 8 && buffer[1] == 6;
}

void process_arp(int type) {
	if (type == ARP_REQUEST) {
		arp_request_count++;
	}
	if (type == ARP_REPLY) {
		arp_reply_count++;
	}
	int total = arp_reply_count + arp_request_count;
	arp_request_percentage = arp_request_count * 100 / total;
	arp_reply_percentage = 100 - arp_request_percentage;
}

void print_statistics() {
	printf("number of arp requests: %d\n", arp_request_count);
	printf("number of arp replies: %d\n", arp_reply_count);
	printf("percentage of arp requests: %d%%\n", arp_request_percentage);
	printf("percentage of arp replies: %d%%\n", arp_reply_percentage);
}

int main(int argc,char *argv[])
{
    if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    	printf("Erro na criacao do socket.\n");
		exit(1);
    }

	strcpy(ifr.ifr_name, "wlan0");
	if(ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
		printf("erro no ioctl!");
	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);

	while (1) {
		recv(sockd,(char *) &buffer, sizeof(buffer), 0x0);
		// printf("MAC Destino: %x:%x:%x:%x:%x:%x \n", buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],buffer[5]);
		// printf("MAC Origem:  %x:%x:%x:%x:%x:%x \n", buffer[6],buffer[7],buffer[8],buffer[9],buffer[10],buffer[11]);
		//
		// if (is_ipv4(&buffer[ETH_TYPE_INDEX])) {
		// 	printf("ipv4");
		//
		// }
		if (is_arp(&buffer[ETH_TYPE_INDEX])) {
			process_arp(buffer[ARP_TYPE_INDEX]);
			print_statistics();
		}

		// printf("\n");
	}
}
