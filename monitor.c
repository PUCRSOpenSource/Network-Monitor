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

int tcp_ports[IP_LIST_SIZE];
int udp_ports[IP_LIST_SIZE];
int tcp_port_num_access[IP_LIST_SIZE];
int udp_port_num_access[IP_LIST_SIZE];

int sockd;
int on;
struct ifreq ifr;

void init();
bool is_ipv4(unsigned char *buffer);
bool is_arp(unsigned char *buffer);
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
void add_tcp_port(int port);
void add_udp_port(int port);
int least_accessed_tcp_port_index();
int least_accessed_udp_port_index();
void print_statistics();
void print_tcp_ports();
void print_udp_ports();
void most_accessed_tcp_port_indexes(int *most_accessed_indexes);
void most_accessed_udp_port_indexes(int *most_accessed_indexes);
void process_percentages();

void init() {
	for (size_t i = 0; i < IP_LIST_SIZE; i++) {
		ip_num_access[i] = 0;
		tcp_port_num_access[i] = 0;
		tcp_ports[i] = 0;
		udp_port_num_access[i] = 0;
		udp_ports[i] = 0;
		for (size_t j = 0; j < 4; j++) {
			ips[i][j] = 0;
		}
	}
}

bool is_ipv4(unsigned char *buffer) {
	return buffer[0] == 8 && buffer[1] == 0;
}

bool is_arp(unsigned char *buffer) {
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

void add_tcp_port(int port) {
	for (size_t i = 0; i < IP_LIST_SIZE; i++) {
		if (port == tcp_ports[i]) {
			tcp_port_num_access[i]++;
			return;
		}
	}
	int index = least_accessed_tcp_port_index();
	tcp_ports[index] = port;
	tcp_port_num_access[index] = 1;
}

void add_udp_port(int port) {
	for (size_t i = 0; i < IP_LIST_SIZE; i++) {
		if (port == udp_ports[i]) {
			udp_port_num_access[i]++;
			return;
		}
	}
	int index = least_accessed_udp_port_index();
	udp_ports[index] = port;
	udp_port_num_access[index] = 1;
}


int least_accessed_tcp_port_index() {
	int lowest_index = 0;
	int lowest_value = tcp_port_num_access[lowest_index];
	for (size_t i = 0; i < IP_LIST_SIZE; i++) {
		if (tcp_port_num_access[i] < lowest_value) {
			lowest_value = tcp_port_num_access[i];
			lowest_index = i;
		}
	}
	return lowest_index;
}

int least_accessed_udp_port_index() {
	int lowest_index = 0;
	int lowest_value = udp_port_num_access[lowest_index];
	for (size_t i = 0; i < IP_LIST_SIZE; i++) {
		if (udp_port_num_access[i] < lowest_value) {
			lowest_value = udp_port_num_access[i];
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

void print_tcp_ports() {
	int indexes[5] = {-1, -1, -1, -1, -1};
	most_accessed_tcp_port_indexes(indexes);
	printf("----------------------\n");
	for (size_t i = 0; i < 5; i++) {
		if (indexes[i] >= 0) {
			printf("PORT: %d\n", tcp_ports[indexes[i]]);
			printf("Accessed %d times\n", tcp_port_num_access[indexes[i]]);
		}
	}
	printf("----------------------\n");
}

void print_udp_ports() {
	int indexes[5] = {-1, -1, -1, -1, -1};
	most_accessed_udp_port_indexes(indexes);
	printf("----------------------\n");
	for (size_t i = 0; i < 5; i++) {
		if (indexes[i] >= 0) {
			printf("PORT: %d\n", udp_ports[indexes[i]]);
			printf("Accessed %d times\n", udp_port_num_access[indexes[i]]);
		}
	}
	printf("----------------------\n");
}

void most_accessed_tcp_port_indexes(int *most_accessed_indexes) {
	for (size_t i = 0; i < IP_LIST_SIZE; i++) {
		if (tcp_port_num_access[i] == 0) {
			continue;
		}
		for (size_t j = 0; j < 5; j++) {
			if (most_accessed_indexes[j] == -1) {
				most_accessed_indexes[j] = i;
				break;
			}
			if (tcp_port_num_access[i] > tcp_port_num_access[most_accessed_indexes[j]]) {
				most_accessed_indexes[j] = i;
				break;
			}
		}
	}
}

void most_accessed_udp_port_indexes(int *most_accessed_indexes) {
	for (size_t i = 0; i < IP_LIST_SIZE; i++) {
		if (udp_port_num_access[i] == 0) {
			continue;
		}
		for (size_t j = 0; j < 5; j++) {
			if (most_accessed_indexes[j] == -1) {
				most_accessed_indexes[j] = i;
				break;
			}
			if (udp_port_num_access[i] > udp_port_num_access[most_accessed_indexes[j]]) {
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
	printf("Tamanho mínimo do pacote: %d\n", min_package_size);
	printf("Tamanho máximo do pacote: %d\n", max_package_size);
	printf("Média do tamanho dos pacotes: %d\n", avarage_package_size);
	printf("\n");

	printf("Nivel de enlace\n");
	printf("Número de ARP Requests: %d\n", arp_request_count);
	printf("Número de ARP Replies: %d\n", arp_reply_count);
	printf("Percentual de ARP Requests: %d%%\n", arp_request_percentage);
	printf("Percentual de ARP Replies: %d%%\n", arp_reply_percentage);
	printf("\n");

	printf("Nivel de rede\n");
	printf("Número de pacotes ICMP: %d\n", icmp_count);
	printf("Percentual de pacotes ICMP: %d%%\n", icmp_percentage);
	printf("Número de ICMP ECHO Requests: %d\n", icmp_echo_request_count);
	printf("Percentual de ICMP ECHO Requests: %d%%\n", icmp_echo_request_percentage);
	printf("Número de ICMP ECHO Replies: %d\n", icmp_echo_reply_count);
	printf("Percentual de ICMP ECHO Replies: %d%%\n", icmp_echo_reply_percentage);
	printf("5 IPS mais acessados: \n");
	print_ips();
	printf("\n");

	printf("Nível de Transporte\n");
	printf("Número de pacotes TCP: %d\n", tcp_count);
	printf("Percentual de pacotes TCP: %d%%\n", tcp_percentage);
	printf("Número de pacotes UDP: %d\n", udp_count);
	printf("Percentual de pacotes UDP: %d%%\n", udp_percentage);
	printf("Portas TCP mais acessadas\n");
	print_tcp_ports();
	printf("Portas UDP mais acessadas\n");
	print_udp_ports();
	printf("\n");

	printf("Nivel de aplicação\n");
	printf("Número de pacotes HTTP: %d\n", http_count);
	printf("Percentual de pacotes HTTP: %d%%\n", http_percentage);
	printf("Número de pacotes DNS: %d\n", dns_count);
	printf("Percentual de pacotes DNS: %d%%\n", dns_percentage);
	printf("\n");
}

int main(int argc,char *argv[])
{

	if(argc <= 2) {
		printf("Formato: ./arquivo interface numero-de-pacotes\n");
		return 0;
	}

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
		i++;
		if(i > atoi(argv[2])) break;
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
				add_udp_port(src_port);
				add_udp_port(dst_port);
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
				add_tcp_port(src_port);
				add_tcp_port(dst_port);
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
