/*
        Raw UDP sockets
*/
#include <arpa/inet.h>
#include <errno.h>        //For errno - the error number
#include <netinet/ip.h>   //Provides declarations for ip header
#include <netinet/udp.h>  //Provides declarations for udp header
#include <stdio.h>        //for printf
#include <stdlib.h>       //for exit(0);
#include <string.h>       //memset
#include <sys/socket.h>   //for socket ofcourse

#include <iostream>

#define MAX_BUFFER 4096
/*
        96 bit (12 bytes) pseudo header needed for udp header checksum calculation
*/

struct pseudo_header {
        u_int32_t source_address;
        u_int32_t dest_address;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t udp_length;
};

/*
        Generic checksum calculation function
*/

unsigned short csum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return (answer);
}

void hexdump(void *ptr, int buflen) {
    unsigned char *buf = (unsigned char *)ptr;
    int i, j;
    for (i = 0; i < buflen; i += 16) {
        printf("%06x: ", i);
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%02x ", buf[i + j]);
            else
                printf("   ");
        printf(" ");
        for (j = 0; j < 16; j++)
            if (i + j < buflen) printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
        printf("\n");
    }
}

int main(void) {
    // Create a raw socket of type IPPROTO
    int rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (rawSocket == -1) {
        // socket creation failed, may be because of non-root privileges
        perror("Failed to create raw socket");
        exit(1);
    }

    /*
     * Don't know what this does
     */
    int one = 1;
    const int *val = &one;
    if (setsockopt(rawSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("Error setting IP_HDRINCL");
        exit(0);
    }

    /*
     * Setup receive timout for socket
     */
    struct timeval timeout;
    timeout.tv_sec = 1;   ///* seconds */
    timeout.tv_usec = 0;  ///* microseconds */

    if (setsockopt(rawSocket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0) {
        perror("Setsockopt failed\n");
    }

    // Datagram to represent the packet
    char datagram[4096], source_ip[32], *data, *pseudogram;

    // zero out the packet buffer
    memset(datagram, 0, 4096);

    // IP header
    struct ip *iph = (struct ip *)datagram;

    // UDP header
    struct udphdr *udph = (struct udphdr *)(datagram + sizeof(struct ip));

    struct sockaddr_in sin;
    struct pseudo_header psh;

    // Data part
    data = datagram + sizeof(struct ip) + sizeof(struct udphdr);
    strcpy(data, "$group_6$");

    // some address resolution
    strcpy(source_ip, "10.1.19.34");

    sin.sin_family = AF_INET;
    sin.sin_port = htons(4026);
    sin.sin_addr.s_addr = inet_addr("130.208.242.120");

    // Fill in the IP Header
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + strlen(data);
    iph->ip_id = htons(54321);  // 54321
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = inet_addr(source_ip);
    iph->ip_dst.s_addr = sin.sin_addr.s_addr;

    // Ip checksum
    iph->ip_sum = csum((unsigned short *)datagram, iph->ip_len);

    // UDP header
    udph->uh_sport = htons(55349);
    udph->uh_dport = htons(4026);
    udph->uh_ulen = htons(8 + strlen(data));  // tcp header size
    udph->uh_sum = 0;                         // leave checksum 0 now, filled later by pseudo header

    // Now the UDP checksum using the pseudo header
    psh.source_address = inet_addr(source_ip);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.protocol = IPPROTO_UDP;
    psh.placeholder = 0;
    psh.udp_length = htons(sizeof(struct udphdr) + strlen(data));

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
    pseudogram = (char *)malloc(psize);

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr) + strlen(data));

    udph->uh_sum = csum((unsigned short *)pseudogram, psize);

    // loop if you want to flood :)
    int tries = 0;
    int max_tries = 5;
    // while (tries < max_tries)
    {
        // Send the packet
        if (sendto(rawSocket, datagram, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            perror("sendto failed");
        }
        // Data send successfully
        else {
            printf("Packet sent.\nLength : %d \n", iph->ip_len);

            char buffer[MAX_BUFFER];
            socklen_t addr_len = sizeof(sin);
            ssize_t bytesReceived =
                recvfrom(rawSocket, buffer, sizeof(buffer), 0, (sockaddr *)&sin,
                         &addr_len);  // recv(rawSocket, (char *)buffer, MAX_BUFFER, 0);
            // hexdump(&buffer, MAX_BUFFER);
            std::cout << "buffer: " << buffer << std::endl;

            if (bytesReceived < 0) {
                printf("Receive error: %s\n ", strerror(errno));
            } else {
                printf("%s\n", buffer);
            }
        }
        // tries++;
    }

    return 0;
}

// Complete