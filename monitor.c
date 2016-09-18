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
#define IP_PROTOCOL_INDEX 23
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0


unsigned char buffer[BUFFSIZE];

int min_package_size = 32767;
int max_package_size = 0;
int avarage_package_size = 0;
int number_of_packages = 0;

int arp_request_count = 0;
int arp_request_percentage = 50;
int arp_reply_count = 0;
int arp_reply_percentage = 50;

int icmp_count = 0;
int icmp_echo_request_count = 0;
int icmp_echo_reply_count = 0;

int udp_count = 0;
int tcp_count = 0;

int sockd;
int on;
struct ifreq ifr;

bool is_ipv4(char *buffer) {
	return buffer[0] == 8 && buffer[1] == 0;
}

bool is_arp(char *buffer) {
	return buffer[0] == 8 && buffer[1] == 6;
}

bool is_icmp(int protocol) {
	return protocol == 1;
}

bool is_tcp(int protocol) {
	return protocol == 6;
}

bool is_udp(int protocol) {
	return protocol == 17;
}

void process_package_size(ssize_t size) {
	number_of_packages++;
	if (size < min_package_size) {
		min_package_size = size;
	}
	if (size > max_package_size) {
		max_package_size = size;
	}
	avarage_package_size = (avarage_package_size * (number_of_packages - 1) + size) / number_of_packages;
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

void process_icmp(int type) {
	icmp_count++;
	if (type == ICMP_ECHO_REQUEST) {
		icmp_echo_request_count++;
	}
	if (type == ICMP_ECHO_REPLY) {
		icmp_echo_reply_count++;
	}
}

void process_udp() {
	udp_count++;
}

void process_tcp() {
	tcp_count++;
}

void print_statistics() {
	printf("Geral\n");
	printf("max package size: %d\n", max_package_size);
	printf("min package size: %d\n", min_package_size);
	printf("avarage package size: %d\n", avarage_package_size);
	printf("Nivel de enlace\n");
	printf("number of arp requests: %d\n", arp_request_count);
	printf("number of arp replies: %d\n", arp_reply_count);
	printf("percentage of arp requests: %d%%\n", arp_request_percentage);
	printf("percentage of arp replies: %d%%\n", arp_reply_percentage);
	printf("Nivel de rede\n");
	printf("number of icmp: %d\n", icmp_count);
	printf("number of icmp echo requests: %d\n", icmp_echo_request_count);
	printf("number of icmp echo replies: %d\n", icmp_echo_reply_count);
	printf("\n");
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
		ssize_t package_size = recv(sockd,(char *) &buffer, sizeof(buffer), 0x0);
		process_package_size(package_size);

		// printf("MAC Destino: %x:%x:%x:%x:%x:%x \n", buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],buffer[5]);
		// printf("MAC Origem:  %x:%x:%x:%x:%x:%x \n", buffer[6],buffer[7],buffer[8],buffer[9],buffer[10],buffer[11]);

		if (is_ipv4(&buffer[ETH_TYPE_INDEX])) {
			if (is_icmp(buffer[IP_PROTOCOL_INDEX])) {
				process_icmp(buffer[34]);
			}
			if (is_udp(buffer[IP_PROTOCOL_INDEX])) {
				process_udp();
			}
			if (is_tcp(buffer[IP_PROTOCOL_INDEX])) {
				process_tcp();
			}

			printf("ip source %d.%d.%d.%d\n", buffer[26], buffer[27], buffer[28], buffer[29]);
			printf("ip destination %d.%d.%d.%d\n", buffer[30], buffer[31], buffer[32], buffer[33]);
		}
		if (is_arp(&buffer[ETH_TYPE_INDEX])) {
			process_arp(buffer[ARP_TYPE_INDEX]);
		}

		// print_statistics();
	}
}
