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

unsigned char buffer[BUFFSIZE];

int sockd;
int on;
struct ifreq ifr;

bool isIPV4(char *buffer) {
	return buffer[0] == 8 && buffer[1] == 0;
}

bool isARP(char *buffer) {
	return buffer[0] == 8 && buffer[1] == 6;
}

int main(int argc,char *argv[])
{
    if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    	printf("Erro na criacao do socket.\n");
		exit(1);
    }

	strcpy(ifr.ifr_name, "eth0");
	if(ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
		printf("erro no ioctl!");
	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);

	while (1) {
		recv(sockd,(char *) &buffer, sizeof(buffer), 0x0);
		printf("MAC Destino: %x:%x:%x:%x:%x:%x \n", buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],buffer[5]);
		printf("MAC Origem:  %x:%x:%x:%x:%x:%x \n", buffer[6],buffer[7],buffer[8],buffer[9],buffer[10],buffer[11]);
		printf("Type:  %x:%x \n", buffer[12],buffer[13]);
		if (isIPV4(&buffer[12])) {
			printf("ipv4");
		}
		if (isARP(&buffer[12])) {
			printf("arp");
		}

		printf("\n");
	}
}
