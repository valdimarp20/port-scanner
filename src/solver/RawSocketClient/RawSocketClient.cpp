#include "RawSocketClient.h"

#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#include <iostream>

#include "../../shared/SocketException.h"

RawSocketClient::RawSocketClient(const char *destinationIpAddress) {
    this->destinationIpAddress = destinationIpAddress;
}

RawSocketClient::~RawSocketClient() {}

void RawSocketClient::createSocket() {
    try {
        buildSocket();
        setIncludeHeaderDataOption();
        buildDestinationAddress();
    } catch (SocketException &exception) {
        std::cerr << exception.what() << std::endl;
        exit(1);
    }
}

// SOCKET
void RawSocketClient::buildSocket() {
    socket = ::socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (socket < 0) {
        throw SocketException(strerror(errno));
    }
}

void RawSocketClient::setIncludeHeaderDataOption() {
    int one = 1;
    const int *val = &one;
    int isOptionSet = setsockopt(socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one));
    if (isOptionSet < 0) {
        throw SocketException("Error setting IP_HDRINCL");
    }
}

// DESTINATON
void RawSocketClient::setDestinationPort(int port) {
    destinationPort = port;
    buildDestinationPort();
}

void RawSocketClient::buildDestinationPort() {
    destinationAddress.sin_port = htons(destinationPort);
    destinationAddressSize = sizeof(destinationAddress);
}

void RawSocketClient::buildDestinationAddress() {
    destinationAddress.sin_family = AF_INET;
    int isAddressSet = inet_pton(AF_INET, destinationIpAddress, &destinationAddress.sin_addr);

    if (isAddressSet <= 0) {
        if (isAddressSet == 0) {
            throw SocketException("Invalid IPv4 address");
        } else {
            throw SocketException(strerror(errno));
        }
    }
}

// PACKET CRAFTING
unsigned short RawSocketClient::calculateChecksum(unsigned short *buffer, int numBytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while (numBytes > 1) {
        sum += *buffer++;
        numBytes -= 2;
    }
    if (numBytes == 1) {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)buffer;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return (answer);
}

void RawSocketClient::createDatagramAndSend(const char *sourceIpAddress, const char *message) {
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
    strcpy(data, message);

    // some address resolution
    strcpy(source_ip, sourceIpAddress);

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
    iph->ip_dst.s_addr = destinationAddress.sin_addr.s_addr;

    // Ip checksum
    iph->ip_sum = calculateChecksum((unsigned short *)datagram, iph->ip_len);

    // UDP header
    udph->uh_sport = htons(55349);
    udph->uh_dport = htons(4026);
    udph->uh_ulen = htons(8 + strlen(data));  // tcp header size
    udph->uh_sum = 0;                         // leave checksum 0 now, filled later by pseudo header

    // Now the UDP checksum using the pseudo header
    psh.source_address = inet_addr(source_ip);
    psh.dest_address = destinationAddress.sin_addr.s_addr;
    psh.protocol = IPPROTO_UDP;
    psh.placeholder = 0;
    psh.udp_length = htons(sizeof(struct udphdr) + strlen(data));

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
    pseudogram = (char *)malloc(psize);

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr) + strlen(data));

    udph->uh_sum = calculateChecksum((unsigned short *)pseudogram, psize);
    sendto(socket, datagram, iph->ip_len, 0, (struct sockaddr *)&destinationAddress,
           destinationAddressSize);
}