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
#include <time.h>
#include <unistd.h>

#define OK 0
#define ERROR -1

#define MAX_MSG_LENGTH 100

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

#define BOOT_REQUEST 1

#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_ACK      5
#define DHCP_NACK     6

#define OPTION_MESSAGE_TYPE    53
#define OPTION_ADDRESS_REQUEST 50
#define OPTION_SERVER_ID       54

#define BROADCAST_FLAG 0x8000

#define SERVER_PORT 66
#define CLIENT_PORT 68

#define HTYPE 1
#define HLEN  6

unsigned char random_mac[MAX_CHADDR_LENGTH];
u_int32_t transaction_id = 0;
struct in_addr offered_address;

struct in_addr default_gateway;

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
        printf("Could not create socket\n");
        exit(EXIT_FAILURE);
    }

    printf("New socket created\n");

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
    struct ifreq interface;
    strcpy(interface.ifr_ifrn.ifrn_name, interface_name);
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &interface, sizeof(interface)) < 0) {
        printf("\tCould not bind socket to interface %s. Check your privileges...\n", interface_name);
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in client_address = get_address(CLIENT_PORT, INADDR_ANY);
    if (bind(sock, (struct sockaddr *) &client_address, sizeof(client_address)) < 0) {
        printf("\tCould not bind to DHCP socket (port %d)! Check your privileges...\n", CLIENT_PORT);
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
    time_t timeout = 2;
    struct timeval time_val;
    time_val.tv_sec = timeout;
    time_val.tv_usec = 0;

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);

    select(sock + 1, &read_fds, NULL, NULL, &time_val);

    if (!FD_ISSET(sock, &read_fds)) {
        printf("No (more) data received\n");
        return ERROR;
    }
    else {
        socklen_t address_size = sizeof(*source_address);
        memset(source_address, 0, address_size);
        memset(buffer, 0, sizeof(*buffer));
        int received_data =
                (int) recvfrom(sock, buffer, buffer_size, 0, (struct sockaddr *) source_address, &address_size);

        return (received_data == -1) ? ERROR : OK;
    }
}

int make_random_hardware_address() {
    for (int i = 0; i < HLEN; i++) {
        random_mac[i] = rand() % 0x100;
    }

    printf("Random MAC Address: ");
    for (int i = 0; i < HLEN; i++) {
        if (i > 0) {
            printf(":");
        }
        printf("%x", random_mac[i]);
    }
    puts("");

    return OK;
}

void set_magic_cookie(DHCP_packet *packet) {
    packet->options[0] = '\x63';
    packet->options[1] = '\x82';
    packet->options[2] = '\x53';
    packet->options[3] = '\x63';
}

int get_DHCP_reply_packet(int sock, char type);

int send_DHCP_discover_packet(int sock) {
    DHCP_packet discover_packet;
    bzero(&discover_packet, sizeof(discover_packet));

    discover_packet.op = BOOT_REQUEST;
    discover_packet.htype = HTYPE;
    discover_packet.hlen = HLEN;
    discover_packet.hops = 0;

    transaction_id = rand();
    discover_packet.xid = htonl(transaction_id);
    discover_packet.secs = htons(0x00);
    discover_packet.flags = htons(BROADCAST_FLAG);
    memcpy(discover_packet.chaddr, random_mac, HLEN);

    set_magic_cookie(&discover_packet);

    discover_packet.options[4] = OPTION_MESSAGE_TYPE;
    discover_packet.options[5] = 1;
    discover_packet.options[6] = DHCP_DISCOVER;

    discover_packet.options[7] = '\xFF';

    struct sockaddr_in broadcast_address = get_address(SERVER_PORT, INADDR_BROADCAST);
    while (send_packet(&discover_packet, sizeof(discover_packet), sock, &broadcast_address) == ERROR) {
        printf("Error in sending packet... resending the packet\n");
    }

    get_DHCP_reply_packet(sock, DHCP_OFFER);

    return OK;
}

int send_DHCP_request_packet(int sock, struct in_addr server_ip) {
    DHCP_packet request_packet;
    memset(&request_packet, 0, sizeof(request_packet));

    request_packet.op = BOOT_REQUEST;
    request_packet.htype = HTYPE;
    request_packet.hlen = HLEN;
    request_packet.hops = 0;

    request_packet.xid = htonl(transaction_id);

    request_packet.secs = htons(0x00);
    request_packet.flags = htons(BROADCAST_FLAG);
    request_packet.ciaddr = offered_address;
    request_packet.siaddr = server_ip;

    memcpy(request_packet.chaddr, random_mac, HLEN);

    set_magic_cookie(&request_packet);

    request_packet.options[4] = OPTION_MESSAGE_TYPE;
    request_packet.options[5] = 1;
    request_packet.options[6] = DHCP_REQUEST;

    request_packet.options[7] = OPTION_ADDRESS_REQUEST;
    request_packet.options[8] = 4;
    memcpy(request_packet.options+9, &offered_address, 4);

    request_packet.options[13] = OPTION_SERVER_ID;
    request_packet.options[14] = 4;
    memcpy(request_packet.options+15, &server_ip, 4);

    request_packet.options[19] = '\xFF';

    printf("Requesting Address: %s\n", inet_ntoa(offered_address));

    struct sockaddr_in broadcast_address = get_address(SERVER_PORT, INADDR_BROADCAST);
    while (send_packet(&request_packet, sizeof(request_packet), sock, &broadcast_address) == ERROR) {
        printf("Error in sending packet... resending the packet\n");
    }

    get_DHCP_reply_packet(sock, DHCP_ACK);

    return OK;
}

int get_DHCP_reply_packet(int sock, char type) {
    time_t start_time = time(NULL), timeout = 5;
    while (1) {
        time_t current_time = time(NULL);
        if (current_time - start_time > timeout) break;

        DHCP_packet packet;
        struct sockaddr_in source;
        int result = receive_packet(&packet, sizeof(packet), sock, &source);

        if (result == ERROR) return ERROR;
        if (packet.op != 2) continue;

        if (ntohl(packet.xid) != transaction_id) {
            continue;
        }

        result = OK;
        for (int x = 0; x < HLEN; x++) {
            if (packet.chaddr[x] != random_mac[x]) {
                result = ERROR;
                break;
            }
        }

        if (result == ERROR) continue;


        if (type == DHCP_OFFER) {
	    printf("Offered Address:    %s\n", inet_ntoa(packet.yiaddr));
            offered_address = packet.yiaddr;
            send_DHCP_request_packet(sock, source.sin_addr);
        } else if (type == DHCP_ACK) {
            int i = 4;
            while (i < MAX_OPTIONS_LENGTH && packet.options[i] != 3 && packet.options[i] != '\xFF') {
                i++;
                int skip = (int) packet.options[i++];
                while (skip--) i++;
            }
            if (packet.options[i] == '\xFF') return OK;

            default_gateway.s_addr |= ((int) packet.options[i + 2] & 0x000000FF);
            default_gateway.s_addr |= ((int) packet.options[i + 3] & 0x000000FF) << 8;
            default_gateway.s_addr |= ((int) packet.options[i + 4] & 0x000000FF) << 16;
            default_gateway.s_addr |= ((int) packet.options[i + 5] & 0x000000FF) << 24;
        }

        return OK;
    }
    return ERROR;
}

int send_normal_packet(int sock, char *s) {
    struct sockaddr_in default_address = get_address(547, default_gateway.s_addr);
    while (send_packet(s, MAX_MSG_LENGTH, sock, &default_address) == ERROR) {
        printf("Error in sending packet... resending the packet\n");
    }
    return OK;
}

int main() {
    char interface_name[8] = "enp0s3";

    srand(time(NULL));

    printf("Client Starting\n");

    int sock = create_DHCP_socket(interface_name);
    make_random_hardware_address();
    send_DHCP_discover_packet(sock);
    fflush(stdout);

    printf("Default Gateway is: %s\n", inet_ntoa(default_gateway));

    for (int i = 0; i < 5; i++) {
        size_t len = MAX_MSG_LENGTH;
        char *s = (char*)malloc(len);
        printf("Enter message: ");
        fflush(stdout);
        getline(&s, &len, stdin);
        send_normal_packet(sock, s);
        free(s);
    }
    close(sock);

    return 0;
}
