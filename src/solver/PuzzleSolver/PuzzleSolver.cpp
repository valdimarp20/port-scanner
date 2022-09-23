#include "PuzzleSolver.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include <sys/socket.h>

#include <iostream>
#include <vector>

#include "../../scanner/UdpClient/UdpClient.h"
#include "../../shared/SocketException.h"

#define MAX_BUFFER 4096
#define RAW_COMMUNICATION_PORT 45000

unsigned short checkSum(unsigned short *ptr, int nbytes) {
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

PuzzleSolver::PuzzleSolver() {
    this->destIpAddress = "";
}

PuzzleSolver::PuzzleSolver(UdpPortScanner *udpPortScanner) {
    this->udpPortScanner = udpPortScanner;
    scanAndSetPorts();
}

PuzzleSolver::PuzzleSolver(const char *destIpAddress, UdpPortScanner *udpPortScanner)
    : PuzzleSolver(udpPortScanner) {
    this->destIpAddress = destIpAddress;
}

PuzzleSolver::PuzzleSolver(const char *destIpAddress, int port1, int port2, int port3, int port4,
                           UdpPortScanner *udpPortScanner) {
    this->destIpAddress = destIpAddress;
    this->udpPortScanner = udpPortScanner;
    this->udpPortScanner->setOpenPorts({port1, port2, port3, port4});
    scanAndSetPorts();
}

PuzzleSolver::~PuzzleSolver() {}

void PuzzleSolver::scanAndSetPorts() {
    try {
        udpPortScanner->getUdpClient()->setReceiveTimeout(50);
    } catch (SocketException &exception) {
        std::cerr << exception.what() << std::endl;
        exit(1);
    }
    int lowPort = 4000;
    int highPort = 4100;
    int tryEachPortAmount = 5;
    int tries = 0;
    int maxTries = 5;
    bool unableToGetAllPorts = false;

    while (udpPortScanner->getOpenPorts().size() != 4) {
        if (tries >= maxTries) {
            unableToGetAllPorts = true;
            break;
        }
        udpPortScanner->scanPortRange(lowPort, highPort, tryEachPortAmount);
        tries++;
    }

    if (unableToGetAllPorts) {
        std::cout << "Unable to get all four ports..." << std::endl;
        std::cout << "Exiting..." << std::endl;
        exit(EXIT_FAILURE);
    }

    for (int port : udpPortScanner->getOpenPorts()) {
        PortMessagePair portMessagePair = scanAndGetPortMessagePair(port);
        if (portMessagePair.port != -1) {
            portMessagePairs.push_back(portMessagePair);
        }
    }
}

PortMessagePair PuzzleSolver::scanAndGetPortMessagePair(int port) {
    char buffer[MAX_BUFFER];
    memset(buffer, 0, sizeof(buffer));

    PortMessagePair portMessagePair;
    portMessagePair.port = -1;
    portMessagePair.message = "";

    int maxTries = 5, tries = 0, bytesReceived = -1;

    try {
        udpPortScanner->getUdpClient()->setReceiveTimeout(1000);
    } catch (SocketException &exception) {
        std::cerr << exception.what() << std::endl;
        exit(1);
    }
    udpPortScanner->getUdpClient()->setPort(port);

    while (tries < maxTries && bytesReceived < 0) {
        try {
            udpPortScanner->getUdpClient()->send(NULL, 0);
        } catch (SocketException &exception) {
            std::cout << exception.what() << std::endl;
        }
        bytesReceived = udpPortScanner->getUdpClient()->receive(buffer, MAX_BUFFER);
        tries++;
    }

    if (bytesReceived > 0 && udpPortScanner->getUdpClient()->getAddressPort() == port) {
        portMessagePair.port = port;
        portMessagePair.message = buffer;
    }
    return portMessagePair;
}

void PuzzleSolver::printPorts() {
    udpPortScanner->displayOpenPorts();
}

void PuzzleSolver::solveSimplePort(std::string simplePortMessage) {
    std::string secret = simplePortMessage.substr(simplePortMessage.length() - 5);
    int secretPort = stoi(secret);
    secretPorts.push_back(secretPort);

    std::cout << "\tDon't tell the boss that we found the secret port: " << secretPort << std::endl;
}

void PuzzleSolver::solveChecksumPort(PortMessagePair messagePair) {
// Hello, group_6! To get the secret phrase,
// send me a udp message where the payload is a valid UDP IPv4 packet,
// that has a valid UDP checksum of 0xeb41, and with the source address being
// 107.175.100.13! (the last 6 bytes of this message contain this information
// in network order)�Ak�d
#pragma region socket creation
    std::cout << "Original message from port " << messagePair.port << ":" << std::endl;
    std::cout << messagePair.message << "\n" << std::endl;

    // Create udp socket
    std::cout << "Creating up udp socket ... " << std::endl;
    int udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpSocket < 0) {
        std::cout << "failed to create udp socket :(" << std::endl;
        exit(EXIT_FAILURE);
    }
    std::cout << "Udpsocket created successfully !!" << std::endl;

    int milliseconds = 1000;
    timeval timeout;
    timeout.tv_sec = milliseconds / 1000;
    timeout.tv_usec = (milliseconds % 1000) * 1000;

    std::cout << "Setting udp socket timeout to '" << milliseconds << "' milliseconds ..."
              << std::endl;
    int timeoutSet = setsockopt(udpSocket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if (timeoutSet < 0) {
        std::cout << "Failed to set udp socket timeout" << std::endl;
        exit(EXIT_FAILURE);
    }
    std::cout << "Udpsocket timeout set successfully !!" << std::endl;

    struct sockaddr_in udpSocketAddress;
    udpSocketAddress.sin_family = AF_INET;
    udpSocketAddress.sin_port = htons(messagePair.port);

    socklen_t udpSocketAddressSize = sizeof(udpSocketAddress);

    int isUdpSocketAddressSet = inet_pton(AF_INET, destIpAddress, &udpSocketAddress.sin_addr);
    if (isUdpSocketAddressSet < 0) {
        std::cout << "Failed to set udp socket socket address ... " << std::endl;
        exit(EXIT_FAILURE);
    }
#pragma endregion

#pragma region sending group message
    int bytesSent, bytesReceived = -1, tries = 0, maxTries = 10;
    char buffer[MAX_BUFFER];

    while (bytesReceived < 0 && tries < maxTries) {
        std::cout << "Trying to send, for the " << tries << " time" << std::endl;
        bytesSent = sendto(udpSocket, groupMessage.c_str(), groupMessage.size(), 0,
                           (struct sockaddr *)&udpSocketAddress, udpSocketAddressSize);
        bytesReceived = recvfrom(udpSocket, buffer, sizeof(buffer), 0,
                                 (struct sockaddr *)&udpSocketAddress, &udpSocketAddressSize);
        tries++;
    }
    if (bytesSent < 0) {
        std::cout << "No bytes were sent from udpSocket" << std::endl;
        std::cerr << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
    if (bytesReceived < 0) {
        std::cout << "No bytes were received from udpSocket" << std::endl;
        std::cerr << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    } else {
        std::cout << "Got message :" << std::endl << buffer << std::endl;
    }
#pragma endregion

    // std::string lastSixBytesInMessage = stringBuffer.substr(bytesReceived - 6, bytesReceived);
    std::string checksumInMessage;
    std::string ipAddressInMessage;
    std::string stringBuffer(buffer);

    // TODO: find better way to get checksum
    int checksumInMessagePosition = stringBuffer.find("0x");
    checksumInMessage = stringBuffer.substr(checksumInMessagePosition + 2, 4);
    std::cout << "Got checksum: " << checksumInMessage << std::endl;

    int ipAddressMessagePosition = stringBuffer.find("being ");
    ipAddressInMessage = stringBuffer.substr(ipAddressMessagePosition);

    int exclamationPosition = ipAddressInMessage.find("!");
    ipAddressInMessage = ipAddressInMessage.substr(0, exclamationPosition);
    std::cout << "Got ip address: " << ipAddressInMessage << std::endl;

#pragma region creating ipv4 udp packet
    char datagram[4096], *pseudogram;
    memset(datagram, 0, 4096);
    std::cout << "We passed the datagram memset !" << std::endl;

    // IP header
    struct ip *iph = (struct ip *)datagram;

    // UDP header
    struct udphdr *uhdr = (struct udphdr *)(datagram + sizeof(struct ip));

    struct sockaddr_in sin;
    struct pseudo_header psh;

    // Address resolution
    sin.sin_family = AF_INET;
    sin.sin_port = htons(messagePair.port);
    sin.sin_addr.s_addr = inet_addr(destIpAddress);

    // Fill the IP header

    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + 2;
    iph->ip_id = htons(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = inet_addr(ipAddressInMessage.c_str());
    iph->ip_dst.s_addr = sin.sin_addr.s_addr;

    // UDP header
    uhdr->uh_sport = htons(65196);
    uhdr->uh_dport = htons(messagePair.port);
    uhdr->uh_ulen = htons(10);  // htons(sizeof(struct udphdr) + 2);
    uhdr->uh_sum = checkSum((unsigned short *)pseudogram, stoul(checksumInMessage, 0, 16));

    psh.source_address = inet_addr(ipAddressInMessage.c_str());
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + 2);

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + 2;
    pseudogram = (char *)(malloc(psize));

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), uhdr, sizeof(struct udphdr) + 2);

    std::string *messagebuffer;

    unsigned short csumCheck = checkSum((unsigned short *)pseudogram, psize);

    messagebuffer = (std::string *)(datagram + sizeof(ip) + sizeof(udphdr));
    memcpy(messagebuffer, &csumCheck, 2);

    iph->ip_sum = htons(checkSum((unsigned short *)datagram, iph->ip_len));

    bytesReceived = -1;
    tries = 0;
    bytesSent = -1;

    memset(buffer, 0, sizeof(buffer));
    while (bytesReceived < 0 && tries < maxTries) {
        std::cout << "Trying to send, for the " << tries << " time" << std::endl;
        bytesSent = sendto(udpSocket, datagram, psize, 0, (struct sockaddr *)&udpSocketAddress,
                           udpSocketAddressSize);
        bytesReceived = recvfrom(udpSocket, buffer, sizeof(buffer), 0,
                                 (struct sockaddr *)&udpSocketAddress, &udpSocketAddressSize);
        tries++;
    }
    if (bytesSent < 0) {
        std::cout << "No bytes were sent from udpSocket" << std::endl;
        std::cerr << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
    if (bytesReceived < 0) {
        std::cout << "No bytes were received from udpSocket" << std::endl;
        std::cerr << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    } else {
        std::cout << "Got message :" << std::endl << buffer << std::endl;
    }

#pragma endregion
}

void PuzzleSolver::solveEvilBitPort(PortMessagePair messagePair) {
    std::cout << "The following was the originial message from port " << messagePair.port << ":"
              << std::endl;

    std::cout << messagePair.message << "\n" << std::endl;

    std::cout << "Setting up an appropriate response..." << std::endl;

    int rawSendSocket;
    if ((rawSendSocket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
        std::cout << "Failed to create socket" << std::endl;
        std::cout << strerror(errno) << std::endl;
        exit(1);
    }

    struct sockaddr_in local_addr {};
    int local_addr_size = sizeof(local_addr);
    // Get local ip address
    getsockname(rawSendSocket, (struct sockaddr *)&local_addr, (socklen_t *)&local_addr_size);

    char datagram[4096], *data1, *pseudogram;

    memset(datagram, 0, 4096);

    // IP header
    struct ip *iph = (struct ip *)datagram;

    // UDP header
    struct udphdr *uhdr = (struct udphdr *)(datagram + sizeof(struct ip));

    struct sockaddr_in sin;
    struct pseudo_header psh;

    // Data
    data1 = (datagram + sizeof(struct ip)) + sizeof(struct udphdr);
    strcpy(data1, "$group_6$");

    // Address resolution

    sin.sin_family = AF_INET;
    sin.sin_port = htons(messagePair.port);
    sin.sin_addr.s_addr = inet_addr(destIpAddress);

    // Fill the IP header

    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + strlen(data1);
    iph->ip_id = htons(54321);
    iph->ip_off = 0x8000;  // htons(0x80);   Evil bit
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = local_addr.sin_addr.s_addr;  // INADDR_ANY;
    iph->ip_dst.s_addr = sin.sin_addr.s_addr;

    // Checksum

    iph->ip_sum = checkSum((unsigned short *)datagram, iph->ip_len);

    // UDP header

    uhdr->uh_sport = htons(RAW_COMMUNICATION_PORT);
    uhdr->uh_dport = htons(messagePair.port);
    uhdr->uh_ulen = htons(sizeof(struct udphdr) + strlen(data1));
    uhdr->uh_sum = 0;  // leave checksum 0 now, filled later by pseudo header

    psh.source_address = local_addr.sin_addr.s_addr;
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + strlen(data1));

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data1);
    pseudogram = (char *)(malloc(psize));

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), uhdr, sizeof(struct udphdr) + strlen(data1));
    //  udph->uh_sum = htons((unsigned short)stoul(stringChecksum, 0, 16)); // The checksum given in
    //  the text
    uhdr->uh_sum = checkSum((unsigned short *)pseudogram, psize);

    // IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt(rawSendSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        std::cout << "Error setting IP_HDRINCL" << std::endl;
        exit(1);
    }

    int bytesReceived1 = -1;
    int tries1 = 1;
    int maxTries1 = 10;
    bool unableToGetResponse1 = false;

    UdpClient client = UdpClient(inet_ntoa(local_addr.sin_addr), RAW_COMMUNICATION_PORT);

    client.setReceiveTimeout(1000);
    client.bindSocket();
    // udpPortScanner->getUdpClient()->setPort(RAW_COMMUNICATION_PORT);
    char responseMessageBuffer[4096];
    while (bytesReceived1 < 0) {
        memset(responseMessageBuffer, 0, sizeof(responseMessageBuffer));
        if (tries1 >= maxTries1) {
            unableToGetResponse1 = true;
            break;
        }
        std::cout << "Trying to get a response from port " << messagePair.port
                  << " via raw packet (tries: " << tries1 << ")..." << std::endl;

        // sendto(raw_sock, &packet, (sizeof(struct ip) + sizeof(struct udphdr) +
        // strlen(evil_data)), 0, (const struct sockaddr *)&dest_addr, sizeof(dest_addr))

        // sendto(rawSendSocket, datagram, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin));

        sendto(rawSendSocket, &datagram,
               (sizeof(struct ip) + sizeof(struct udphdr) + strlen(data1)), 0,
               (struct sockaddr *)&sin, sizeof(sin));

        bytesReceived1 = client.receive(responseMessageBuffer, MAX_BUFFER);
        tries1++;
    }

    if (unableToGetResponse1) {
        std::cout << "Unable to recieve whilst sending a raw udp packet via port "
                  << messagePair.port << "..." << std::endl;
        return;
    }

    std::cout << "Port " << messagePair.port
              << " responded with the following message:" << std::endl;
    std::cout << responseMessageBuffer << std::endl;

    std::cout << "Secret port from Evil puzzle is:" << std::endl;

    std::cout << responseMessageBuffer << std::endl;

    std::string message = std::string(responseMessageBuffer);
    int startPos = message.find(":");
    int endPos = strlen(message.c_str());

    std::string stringPort = message.substr(startPos + 3, endPos).c_str();

    std::cout << "String port: " << message.substr(startPos + 3, endPos) << std::endl;

    int intPort = atoi(stringPort.c_str());

    std::cout << "Int port: " << intPort << std::endl;

    /*
    initializing udpportscanner
    --------------------------------
    Evil bit port:  4052
    --------------------------------
    --------------------------------
    Port 4052 is the evil bit phase
    The following was the originial message from port 4052:
    The dark side of network programming is a pathway to many abilities some consider to
    be...unnatural. (https://en.wikipedia.org/wiki/Evil_bit) Send us a message containing your group
    number in the form
    "$group_#$" where # is your group number.

    Setting up an appropriate response...
    Trying to get a response from port 4052 via raw packet (tries: 1)...
    Port 4052 responded with the following message:
    0x7ff7b14694e0
    */
}

void PuzzleSolver::printPuzzlePorts() {
    std::cout << "--------------------------------" << std::endl;
    for (PortMessagePair &puzzle : portMessagePairs) {
        if (puzzle.message.find("Send me a message") != std::string::npos) {
            std::cout << "Checksum port:\t" << puzzle.port << std::endl;
        } else if (puzzle.message.find("I am the oracle") != std::string::npos) {
            std::cout << "Oracle port:\t" << puzzle.port << std::endl;
        } else if (puzzle.message.find("The dark side") != std::string::npos) {
            std::cout << "Evil bit port:\t" << puzzle.port << std::endl;
        } else if (puzzle.message.find("My boss") != std::string::npos) {
            std::cout << "Simple port:\t" << puzzle.port << std::endl;
        } else {
            std::cout << "Port:\t" << puzzle.port << "unexepected ..." << std::endl;
        }
    }
    std::cout << "--------------------------------" << std::endl;
}

void PuzzleSolver::solvePuzzles() {
    std::cout << "--------------------------------" << std::endl;

    for (PortMessagePair portMessagePair : portMessagePairs) {
        udpPortScanner->getUdpClient()->setPort(portMessagePair.port);
        if (portMessagePair.message.find("Send me a message") != std::string::npos) {
            continue;
        } else if (portMessagePair.message.find("I am the oracle") != std::string::npos) {
            continue;
        } else if (portMessagePair.message.find("The dark side") != std::string::npos) {
            solveEvilBitPort(portMessagePair);
        } else if (portMessagePair.message.find("My boss") != std::string::npos) {
            std::cout << "------ SOLVING SIMPLE PORT -----" << std::endl;
            solveSimplePort(portMessagePair.message);
            std::cout << "--------------------------------" << std::endl;
        } else {
            std::cout << "Port " << portMessagePair.port << " is the an unknown phase..."
                      << std::endl;
        }
    }
}

void PuzzleSolver::test() {
    int rawSendSocket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

    if (rawSendSocket == -1) {
        // socket creation failed, may be because of non-root privileges
        perror("Failed to create socket, make sure you are running with root privileges.");
        exit(1);
    }

    int dest_port = 4052;
    int source_port = 51192;

    // Datagram to represent my package
    char datagram[4096], source_ip[32], *data, *pseudogram;

    memset(datagram, 0, 4096);

    // IP header
    struct ip *iph = (struct ip *)datagram;

    // UDP header
    struct udphdr *uhdr = (struct udphdr *)(datagram + sizeof(struct ip));

    struct sockaddr_in sin;
    struct pseudo_header psh;

    // Data
    data = (datagram + sizeof(struct ip)) + sizeof(struct udphdr);
    strcpy(data, "$group_6$");

    // address resolution
    strcpy(source_ip, "10.2.26.155");

    // destination
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dest_port);
    sin.sin_addr.s_addr = inet_addr("130.208.242.120");

    // Fill the IP header
    iph->ip_hl = 5;  // version
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + strlen(data);
    iph->ip_id = htons(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = inet_addr(source_ip);
    iph->ip_dst.s_addr = sin.sin_addr.s_addr;

    // Checksum
    iph->ip_sum = checkSum((unsigned short *)datagram, iph->ip_len);

    // UDP Header
    uhdr->uh_sport = htons(source_port);
    uhdr->uh_dport = htons(dest_port);
    uhdr->uh_ulen = htons(sizeof(struct udphdr) + strlen(data));
    uhdr->uh_sum = 0;  // leave checksum 0 now, filled later by pseudo header

    // Now the UDP checksum
    psh.source_address = inet_addr(source_ip);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + strlen(data));

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
    pseudogram = (char *)(malloc(psize));

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), uhdr, sizeof(struct udphdr) + strlen(data));

    uhdr->uh_sum = checkSum((unsigned short *)pseudogram, psize);

    // set timevalue for timeout
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;

    // IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt(rawSendSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("Error setting IP_HDRINCL");
        exit(0);
    }

    // send the packet
    if (sendto(rawSendSocket, datagram, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto failed");
    }
    // Data sent successfully
    else {
        printf("Packet Sent. Length : %d \n", iph->ip_len);

        int rcv_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        struct sockaddr_in my_address;
        my_address.sin_addr.s_addr = inet_addr("10.2.26.155");
        my_address.sin_family = AF_INET;
        my_address.sin_port = htons(source_port);

        socklen_t socklen = (socklen_t)sizeof(my_address);
        if (bind(rcv_sock, (struct sockaddr *)&my_address, socklen) < 0) {
            perror("bind failed");
            exit(0);
        }

        if (setsockopt(rawSendSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            perror("Error");
        }

        char msg[1024];
        memset(msg, 0, 1024);

        struct sockaddr_in recv_addr {};
        int recv_addr_size = sizeof(recv_addr);

        int bytesReceived = recv(rcv_sock, msg, sizeof(msg), 0);
        if (bytesReceived < 0) {
            printf("RECIEVE ERROR: %s\n ", strerror(errno));
            printf("port = %d\n address = %d\n\n", sin.sin_port, sin.sin_addr.s_addr);
        } else {
            printf("port number: %d\n", dest_port);
            printf("%s\n", msg);
            printf("checksum = ");
            // std::cout << std::hex << iph->ip_sum << std::endl;
            std::cout << bytesReceived << std::endl;
        }

        close(rawSendSocket);
        close(rcv_sock);
        printf("\n-- closed send socket --\n\n");
    }
}