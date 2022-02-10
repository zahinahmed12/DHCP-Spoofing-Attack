#include <arpa/inet.h>
#include <locale.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#define OK 0
#define ERROR -1

#define MAX_CHADDR_LENGTH  16
#define MAX_SNAME_LENGTH   64
#define MAX_FILE_LENGTH    128
#define MAX_OPTIONS_LENGTH 312

struct DHCP_packet {
    u_int8_t op;                             /* packet type */
    u_int8_t htype;                          /* type of hardware address for this machine (Ethernet, etc) */
    u_int8_t hlen;                           /* length of hardware address (of this machine) */
    u_int8_t hops;                           /* hops */
    u_int32_t xid;                           /* random transaction id number - chosen by this machine */
    u_int16_t secs;                          /* seconds used in timing */
    u_int16_t flags;                         /* flags */
    struct in_addr ciaddr;                   /* IP address of this machine (if we already have one) */
    struct in_addr yiaddr;                   /* IP address of this machine (offered by the DHCP server) */
    struct in_addr siaddr;                   /* IP address of DHCP server */
    struct in_addr giaddr;                   /* IP address of DHCP relay */
    unsigned char chaddr[MAX_CHADDR_LENGTH]; /* hardware address of this machine */
    char sname[MAX_SNAME_LENGTH];            /* name of DHCP server */
    char file[MAX_FILE_LENGTH];              /* boot file name (used for disk-less booting?) */
    char options[MAX_OPTIONS_LENGTH];        /* options */
};
typedef struct DHCP_packet DHCP_packet;

#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_ACK      5
#define DHCP_NACK     6

#define BROADCAST_FLAG 0x8000

#define SERVER_PORT 67
#define CLIENT_PORT 68

#define HTYPE 1
#define HLEN  6

#define OPTION_ADDRESS_REQUEST 50
#define OPTION_LEASE_TIME 51
#define OPTION_MESSAGE_TYPE    53

#define OPTION_SERVER_ID       54
#define OPTION_DEFAULT_GATEWAY_ROUTER_ID 3
#define OPTION_DNS_SERVER_ID 6

#define START_IP 101
#define END_IP 150

struct ifreq interface;
struct in_addr server_ip;
int offer_count = START_IP;
int normal;

unsigned char random_mac[MAX_CHADDR_LENGTH];
u_int32_t transaction_id = 0;
struct in_addr offered_address;

struct sockaddr_in get_address(in_port_t port, in_addr_t ip) {
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = ip;
    bzero(&address.sin_zero, sizeof(address.sin_zero));
    return address;
}

int create_DHCP_socket(char *interface_name) {
    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("Could not create DHCP socket\n");
        exit(EXIT_FAILURE);
    }

    printf("New DHCP socket created\n");

    int opt_val = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val)) < 0) {
        printf(" Could not set reuse address option on DHCP socket!\n");
        exit(EXIT_FAILURE);
    }
    opt_val = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt_val, sizeof opt_val) < 0) {
        printf(" Could not set broadcast option on DHCP socket!\n");
        exit(EXIT_FAILURE);
    }
    strcpy(interface.ifr_ifrn.ifrn_name, interface_name);
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &interface, sizeof(interface)) < 0) {
        printf("\tCould not bind socket to interface %s. Check your privileges...\n", interface_name);
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in client_address = get_address(SERVER_PORT, INADDR_ANY);
    if (bind(sock, (struct sockaddr *) &client_address, sizeof(client_address)) < 0) {
        printf("\tCould not bind to DHCP socket (port %d)! Check your privileges...\n", SERVER_PORT);
        exit(EXIT_FAILURE);
    }

    return sock;
}

int create_normal_socket(char *interface_name) {
    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("Could not create Communication socket\n");
        exit(EXIT_FAILURE);
    }

    printf("New Communication socket created\n");

    int opt_val = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val)) < 0) {
        printf(" Could not set reuse address option on DHCP socket!\n");
        exit(EXIT_FAILURE);
    }
    opt_val = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt_val, sizeof opt_val) < 0) {
        printf(" Could not set broadcast option on DHCP socket!\n");
        exit(EXIT_FAILURE);
    }
    strcpy(interface.ifr_ifrn.ifrn_name, interface_name);
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &interface, sizeof(interface)) < 0) {
        printf("\tCould not bind socket to interface %s. Check your privileges...\n", interface_name);
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in client_address = get_address(547, INADDR_ANY);
    if (bind(sock, (struct sockaddr *) &client_address, sizeof(client_address)) < 0) {
        printf("\tCould not bind to DHCP socket (port %d)! Check your privileges...\n", 547);
        exit(EXIT_FAILURE);
    }

    return sock;
}

int send_packet(void *buffer, int buffer_size, int sock, struct sockaddr_in *dest) {
    int result = (int) sendto(sock, buffer, buffer_size, 0, (struct sockaddr *) dest, sizeof(*dest));

    if (result < 0) {
        return ERROR;
    }
    return OK;
}

int receive_packet(void *buffer, size_t buffer_size, int sock, struct sockaddr_in *source_address) {
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);
    FD_SET(normal, &read_fds);

    select((sock > normal ? sock : normal) + 1, &read_fds, NULL, NULL, NULL);

    if (FD_ISSET(normal, &read_fds)) {
        socklen_t address_size = sizeof(*source_address);
        memset(source_address, 0, address_size);
        memset(buffer, 0, sizeof(*buffer));
        int received_data =
                (int) recvfrom(normal, buffer, 100, 0, (struct sockaddr *) source_address, &address_size);
        if (received_data == -1) return ERROR;
        printf("Message from client: %s", (char *)buffer);//inet_ntoa(source_address->sin_addr)
        fflush(stdout);
        return OK;
    }
    else if (FD_ISSET(sock, &read_fds)) {
        socklen_t address_size = sizeof(*source_address);
        memset(source_address, 0, address_size);
        memset(buffer, 0, sizeof(*buffer));
        int received_data =
                (int) recvfrom(sock, buffer, buffer_size, 0, (struct sockaddr *) source_address, &address_size);

        return (received_data == -1) ? ERROR : OK;
    }
    else {
        return ERROR;
    }
}

void set_magic_cookie(DHCP_packet *packet) {
    packet->options[0] = '\x63';
    packet->options[1] = '\x82';
    packet->options[2] = '\x53';
    packet->options[3] = '\x63';
}

void set_server_ip(DHCP_packet *packet, int pos) {
    uint32_t ip = server_ip.s_addr;
    packet->options[pos] = (char) (ip & 0x000000FF);
    ip >>= 8;
    packet->options[pos + 1] = (char) (ip & 0x000000FF);
    ip >>= 8;
    packet->options[pos + 2] = (char) (ip & 0x000000FF);
    ip >>= 8;
    packet->options[pos + 3] = (char) (ip & 0x000000FF);
}

struct in_addr make_offer_ip() {
    struct in_addr addr = server_ip;
    addr.s_addr &= 0x00FFFFFF;
    addr.s_addr |= (offer_count << 24);
    offer_count++;
    return addr;
}

int send_DHCP_reply_packet(int sock, DHCP_packet *packet, char type) {
    packet->op = 2;

    if (type == DHCP_OFFER) {
        packet->ciaddr.s_addr = 0;
        packet->giaddr.s_addr = 0;
        packet->yiaddr = make_offer_ip();
        packet->siaddr = server_ip;
        printf("Offering IP: %s\n", inet_ntoa(packet->yiaddr));
    }
    else if (type == DHCP_ACK) {
        //packet->yiaddr = packet->ciaddr;
	int i = 4;
 	while (i < MAX_OPTIONS_LENGTH && packet->options[i] != 50 && packet->options[i] != '\xFF') {
            i++;
            int skip = (int) packet->options[i++];
            while (skip--) i++;
        }
        if (packet->options[i] == '\xFF') return OK;

        packet->yiaddr.s_addr = 0;
        packet->yiaddr.s_addr |= ((int) packet->options[i + 2] & 0x000000FF);
        packet->yiaddr.s_addr |= ((int) packet->options[i + 3] & 0x000000FF) << 8;
        packet->yiaddr.s_addr |= ((int) packet->options[i + 4] & 0x000000FF) << 16;
        packet->yiaddr.s_addr |= ((int) packet->options[i + 5] & 0x000000FF) << 24;
        
        packet->ciaddr.s_addr = 0;
        packet->giaddr.s_addr = 0;
        packet->siaddr = server_ip;
        printf("Grant IP: %s\n", inet_ntoa(packet->yiaddr));
    }

    bzero(packet->options, sizeof(packet->options));
    set_magic_cookie(packet);

    packet->options[4] = OPTION_MESSAGE_TYPE; // message type
    packet->options[5] = 1;
    packet->options[6] = type;

    packet->options[7] = OPTION_DEFAULT_GATEWAY_ROUTER_ID; // default gateway router IP
    packet->options[8] = 4;
    set_server_ip(packet, 9);

    packet->options[13] = OPTION_LEASE_TIME; // lease time
    packet->options[14] = 4;
    char lease[4] = {120, 0, 0, 0};
    memcpy(packet->options + 15, lease, 4); // time = 120 seconds

    packet->options[13] = OPTION_SERVER_ID; // DHCP server IP
    packet->options[14] = 4;
    set_server_ip(packet, 15);

    packet->options[19] = OPTION_DNS_SERVER_ID; // DNS server IP
    packet->options[20] = 4;
    set_server_ip(packet, 21);

    packet->options[25] = '\xFF';

    struct sockaddr_in broadcast_address = get_address(CLIENT_PORT, INADDR_BROADCAST);
    while (send_packet(packet, sizeof(*packet), sock, &broadcast_address) == ERROR) {
        printf("Error in sending packet... resending the packet\n");
    }

    fflush(stdout);
    return OK;
}

int serve_packet(int sock) {
    DHCP_packet packet;
    struct sockaddr_in source;
    int result = receive_packet(&packet, sizeof(packet), sock, &source);

    if (result == ERROR) return ERROR;
    if (packet.op != 1) return OK;

    if (offer_count > END_IP) return OK;

    int i = 4;
    while (i < MAX_OPTIONS_LENGTH && packet.options[i] != 53 && packet.options[i] != '\xFF') {
        i++;
        int skip = (int) packet.options[i++];
        while (skip--) i++;
    }
    if (packet.options[i] == '\xFF') return OK;

    char type = packet.options[i + 2];

    if (type == DHCP_DISCOVER) {
        printf("DHCP_DISCOVER from client\n");//IP address %s\n", inet_ntoa(source.sin_addr));
        return send_DHCP_reply_packet(sock, &packet, DHCP_OFFER);
    }
    else if (type == DHCP_REQUEST) {
        printf("DHCP_REQUEST  from client\n");//IP address %s\n", inet_ntoa(source.sin_addr));
        return send_DHCP_reply_packet(sock, &packet, DHCP_ACK);
    }

    return OK;
}

int main() {
    char interface_name[8] = "enp0s3";

    srand(time(NULL));

    puts("Fake DHCP Server is starting");

    int sock = create_DHCP_socket(interface_name);
    ioctl(sock, SIOCGIFADDR, &interface);
    server_ip = ((struct sockaddr_in *) &interface.ifr_addr)->sin_addr;

    normal = create_normal_socket(interface_name);
    fflush(stdout);
    printf("My IP address %s\n", inet_ntoa(server_ip));

    while (serve_packet(sock) == OK);

    close(sock);
    close(normal);

    return 0;
}
