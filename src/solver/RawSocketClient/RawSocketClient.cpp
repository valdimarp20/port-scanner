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
    socket = ::socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
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
    // Packet buffer
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));

    // IP header
    struct ip *ipHeader = (struct ip *)buffer;

    // UDP header
    struct udphdr *udpHeader = (struct udphdr *)(buffer + sizeof(struct ip));

    // Data part
    char *data;
    data = buffer + sizeof(struct ip) + sizeof(struct udphdr);
    strcpy(buffer, message);

    // Fill in the IP Header
    ipHeader->ip_hl = 5;
    ipHeader->ip_v = 4;
    ipHeader->ip_tos = 0;
    ipHeader->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + strlen(data);
    ipHeader->ip_id = htons(54321);  // 54321
    ipHeader->ip_off = 0;
    ipHeader->ip_ttl = 64;
    ipHeader->ip_p = IPPROTO_UDP;
    ipHeader->ip_sum = 0;
    inet_pton(AF_INET, sourceIpAddress, &ipHeader->ip_src.s_addr);  // Source address
    ipHeader->ip_dst.s_addr = destinationAddress.sin_addr.s_addr;   // Set destination address
    ipHeader->ip_sum =
        calculateChecksum((unsigned short *)buffer, ipHeader->ip_len);  // Ip checksum

    // Udp header
    udpHeader->uh_sport = htons(55349);  // SOURCE PORT!
    udpHeader->uh_dport = destinationAddress.sin_port;
    udpHeader->uh_ulen = htons(sizeof(struct udphdr) + strlen(data));
    udpHeader->uh_sum = 0;

    // Pseudo header
    struct pseudo_header pseudoHeader;
    char *pseudogram;
    inet_pton(AF_INET, sourceIpAddress, &pseudoHeader.source_address);  // Source address
    pseudoHeader.dest_address = destinationAddress.sin_addr.s_addr;
    pseudoHeader.protocol = IPPROTO_UDP;
    pseudoHeader.placeholder = 0;
    pseudoHeader.udp_length = htons(sizeof(struct udphdr) + strlen(data));

    int packetSize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
    pseudogram = new char[packetSize];

    memcpy(pseudogram, (char *)&pseudoHeader, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udpHeader,
           sizeof(struct udphdr) + strlen(data));
    udpHeader->uh_sum = calculateChecksum((unsigned short *)pseudogram, packetSize);

    delete pseudogram;
    sendto(socket, buffer, ipHeader->ip_len, 0, (struct sockaddr *)&destinationAddress,
           destinationAddressSize);
}