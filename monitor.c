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
#define ICMP_TYPE_INDEX 34
#define IP_SRC_INDEX 26
#define IP_DST_INDEX 30
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0
#define ICMP 1
#define TCP 6
#define UDP 17

#define IP_LIST_SIZE 100


unsigned char buffer[BUFFSIZE];

int min_package_size = 32767;
int max_package_size = 0;
int avarage_package_size = 0;
int number_of_packages = 0;

int arp_request_count = 0;
int arp_request_percentage = 0;
int arp_reply_count = 0;
int arp_reply_percentage = 0;

int icmp_count = 0;
int icmp_percentage = 0;
int icmp_echo_request_count = 0;
int icmp_echo_request_percentage = 0;
int icmp_echo_reply_count = 0;
int icmp_echo_reply_percentage = 0;

int udp_count = 0;
int udp_percentage = 0;
int tcp_count = 0;
int tcp_percentage = 0;

int http_count = 0;
int dns_count = 0;
int http_percentage = 0;
int dns_percentage = 0;

unsigned char ips[IP_LIST_SIZE][4];
int ip_num_access[IP_LIST_SIZE];

int ports[IP_LIST_SIZE];
int port_num_access[IP_LIST_SIZE];

int sockd;
int on;
struct ifreq ifr;

void init();
bool is_ipv4(char *buffer);
bool is_arp(char *buffer);
bool is_icmp(int protocol);
bool is_tcp(int protocol);
bool is_udp(int protocol);
bool is_http(int src_port, int dst_port);
bool is_dns(int src_port, int dst_port);
void process_package_size(ssize_t size);
void process_arp(int type);
void process_icmp(int type);
void process_udp();
void process_tcp();
void process_http();
void process_dns();
int least_accessed_ip_index();
void print_ip(unsigned char *ip);
void copy_ip(unsigned char *ip, unsigned char *buffer);
void add_ip(unsigned char *ip);
void most_accessed_ip_indexes(int *most_accessed_indexes);
void print_ips();
void add_port(int port);
int least_accessed_port_index();
void print_statistics();
void print_ports();
void most_accessed_port_indexes(int *most_accessed_indexes);
void process_percentages();

void init() {
	for (size_t i = 0; i < IP_LIST_SIZE; i++) {
		ip_num_access[i] = 0;
		port_num_access[i] = 0;
		ports[i] = 0;
		for (size_t j = 0; j < 4; j++) {
			ips[i][j] = 0;
		}
	}
}

bool is_ipv4(char *buffer) {
	return buffer[0] == 8 && buffer[1] == 0;
}

bool is_arp(char *buffer) {
	return buffer[0] == 8 && buffer[1] == 6;
}

bool is_icmp(int protocol) {
	return protocol == ICMP;
}

bool is_tcp(int protocol) {
	return protocol == TCP;
}

bool is_udp(int protocol) {
	return protocol == UDP;
}

bool is_http(int src_port, int dst_port) {
	return src_port == 80 || dst_port == 80;
}

bool is_dns(int src_port, int dst_port) {
	return src_port == 53 || dst_port == 53;
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

void process_http() {
	http_count++;
}

void process_dns() {
	dns_count++;
}

void print_ip(unsigned char *ip) {
	printf("ip: %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
}

void add_port(int port) {
	for (size_t i = 0; i < IP_LIST_SIZE; i++) {
		bool match = true;
		if (port == ports[i]) {
			port_num_access[i]++;
			return;
		}
	}
	int index = least_accessed_port_index();
	ports[index] = port;
	port_num_access[index] = 1;
}

int least_accessed_port_index() {
	int lowest_index = 0;
	int lowest_value = port_num_access[lowest_index];
	for (size_t i = 0; i < IP_LIST_SIZE; i++) {
		if (port_num_access[i] < lowest_value) {
			lowest_value = port_num_access[i];
			lowest_index = i;
		}
	}
	return lowest_index;
}


void add_ip(unsigned char *ip) {
	for (size_t i = 0; i < IP_LIST_SIZE; i++) {
		bool match = true;
		for (size_t j = 0; j < 4; j++) {
			if (ip[j] != ips[i][j]) {
				match = false;
			}
		}
		if (match) {
			ip_num_access[i]++;
			return;
		}
	}
	int index = least_accessed_ip_index();
	copy_ip(ip, ips[index]);
	ip_num_access[index] = 1;
}

int least_accessed_ip_index() {
	int lowest_index = 0;
	int lowest_value = ip_num_access[lowest_index];
	for (size_t i = 1; i < IP_LIST_SIZE; i++) {
		if (ip_num_access[i] < lowest_value) {
			lowest_value = ip_num_access[i];
			lowest_index = i;
		}
	}
	return lowest_index;
}

void copy_ip(unsigned char *ip, unsigned char *buffer) {
	for (size_t i = 0; i < 4; i++) {
		buffer[i] = ip[i];
	}
}

void print_ports() {
	int indexes[5] = {-1, -1, -1, -1, -1};
	most_accessed_port_indexes(indexes);
	printf("----------------------\n");
	for (size_t i = 0; i < 5; i++) {
		if (indexes[i] >= 0) {
			printf("PORT: %d\n", ports[indexes[i]]);
			printf("Accessed %d times\n", port_num_access[indexes[i]]);
		}
	}
	printf("----------------------\n");
}

void most_accessed_port_indexes(int *most_accessed_indexes) {
	for (size_t i = 0; i < IP_LIST_SIZE; i++) {
		if (port_num_access[i] == 0) {
			continue;
		}
		for (size_t j = 0; j < 5; j++) {
			if (most_accessed_indexes[j] == -1) {
				most_accessed_indexes[j] = i;
				break;
			}
			if (port_num_access[i] > port_num_access[most_accessed_indexes[j]]) {
				most_accessed_indexes[j] = i;
				break;
			}
		}
	}
}

void print_ips() {
	int indexes[5] = {-1, -1, -1, -1, -1};
	most_accessed_ip_indexes(indexes);
	printf("----------------------\n");
	for (size_t i = 0; i < 5; i++) {
		if (indexes[i] >= 0) {
			printf("IP: %d.%d.%d.%d\n", ips[indexes[i]][0], ips[indexes[i]][1], ips[indexes[i]][2], ips[indexes[i]][3]);
			printf("Accessed %d times\n", ip_num_access[indexes[i]]);
		}
	}
	printf("----------------------\n");
}

void most_accessed_ip_indexes(int *most_accessed_indexes) {
	for (size_t i = 0; i < IP_LIST_SIZE; i++) {
		if (ip_num_access[i] == 0) {
			continue;
		}
		for (size_t j = 0; j < 5; j++) {
			if (most_accessed_indexes[j] == -1) {
				most_accessed_indexes[j] = i;
				break;
			}
			if (ip_num_access[i] > ip_num_access[most_accessed_indexes[j]]) {
				most_accessed_indexes[j] = i;
				break;
			}
		}
	}
}

void process_percentages() {
	arp_request_percentage = arp_request_count * 100 / number_of_packages;
	arp_reply_percentage = arp_reply_count * 100 / number_of_packages;

	icmp_percentage = icmp_count * 100 / number_of_packages;
	icmp_echo_request_percentage = icmp_echo_request_count * 100 / number_of_packages;
	icmp_echo_reply_percentage = icmp_echo_reply_count * 100 / number_of_packages;

	udp_percentage = udp_count * 100 / number_of_packages;
	tcp_percentage = tcp_count * 100 / number_of_packages;
	http_percentage = http_count * 100 / number_of_packages;
	dns_percentage = dns_count * 100 / number_of_packages;
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
	printf("percentage of tcp packages: %d%%\n", icmp_percentage);
	printf("number of icmp echo requests: %d\n", icmp_echo_request_count);
	printf("number of icmp echo replies: %d\n", icmp_echo_reply_count);
	printf("Most accessed ips: \n");
	print_ips();
	printf("Nível de Transporte\n");
	printf("number of tcp packages: %d\n", tcp_count);
	printf("percentage of tcp packages: %d%%\n", tcp_percentage);
	printf("number of udp packages: %d\n", udp_count);
	printf("percentage of udp packages: %d%%\n", udp_percentage);
	printf("Most accessed ports\n");
	print_ports();
	printf("Nivel de aplicação\n");
	printf("number of http packages: %d\n", http_count);
	printf("percentage of http packages: %d\n", http_percentage);
	printf("number of dns packages: %d\n", dns_count);
	printf("percentage of dns packages: %d\n", dns_percentage);
	printf("\n");
}

int main(int argc,char *argv[])
{
    if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    	printf("Erro na criacao do socket.\n");
		exit(1);
    }

	strcpy(ifr.ifr_name, argv[1]);
	if(ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
		printf("erro no ioctl!");
	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);
	init();
	int i = 0;
	while (1) {
		if(i > 50) break;
		i++;
		ssize_t package_size = recv(sockd,(char *) &buffer, sizeof(buffer), 0x0);
		process_package_size(package_size);

		if (is_ipv4(&buffer[ETH_TYPE_INDEX])) {
			if (is_icmp(buffer[IP_PROTOCOL_INDEX])) {
				process_icmp(buffer[ICMP_TYPE_INDEX]);
			}
			if (is_udp(buffer[IP_PROTOCOL_INDEX])) {
				process_udp();
				int src_port = (buffer[34] << 8) + buffer[35];
				int dst_port = (buffer[36] << 8) + buffer[37];

				if (is_dns(src_port, dst_port)) {
					process_dns();
				}
				if (is_http(src_port, dst_port)) {
					process_http();
				}
				add_port(src_port);
				add_port(dst_port);
			}
			if (is_tcp(buffer[IP_PROTOCOL_INDEX])) {
				process_tcp();
				int src_port = (buffer[34] << 8) + buffer[35];
				int dst_port = (buffer[36] << 8) + buffer[37];

				if (is_dns(src_port, dst_port)) {
					process_dns();
				}
				if (is_http(src_port, dst_port)) {
					process_http();
				}
				add_port(src_port);
				add_port(dst_port);
			}
			add_ip(&buffer[IP_SRC_INDEX]);
			add_ip(&buffer[IP_DST_INDEX]);
		}
		if (is_arp(&buffer[ETH_TYPE_INDEX])) {
			process_arp(buffer[ARP_TYPE_INDEX]);
		}

		process_percentages();

	}
	print_statistics();
}
