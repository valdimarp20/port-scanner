#include "PuzzleSolver.h"

#include <iostream>
#include <vector>

#include "../../scanner/UdpClient/UdpClient.h"
#include "../../shared/SocketException.h"
#include "../RawSocketClient/RawSocketClient.h"

#define MAX_BUFFER 4096

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
    unsigned char *buf = (unsigned char*)ptr;
    int i, j;
    for (i=0; i<buflen; i+=16) {
        printf("%06x: ", i);
        for (j=0; j<16; j++)
            if (i+j < buflen)
                printf("%02x ", buf[i+j]);
            else
                printf("   ");
        printf(" ");
        for (j=0; j<16; j++)
            if (i+j < buflen)
                printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
        printf("\n");
    }
}


PuzzleSolver::PuzzleSolver() {
    this->destIpAddress = "";
}

PuzzleSolver::PuzzleSolver(UdpPortScanner *udpPortScanner) {
    // If we are only given the ipAddress, we must find the open ports and assign them
    this->udpPortScanner = udpPortScanner;
    setPortsScan();
}

void PuzzleSolver::setPortsScan() {
    try {
        udpPortScanner->getUdpClient()->setReceiveTimeout(50);
    } catch (SocketException &exception) {
        std::cerr << exception.what() << std::endl;
        exit(1);
    }

    int lowPort = 4000;
    int highPort = 4100;
    udpPortScanner->scanPortRange(lowPort, highPort);

    while (udpPortScanner->getOpenPorts().size() != 4) {
        std::cout << "Something went wrong, didn't get all four ports!" << std::endl;
        std::cout << "These ports are the open ports we found:" << std::endl;
        udpPortScanner->displayOpenPorts();
        std::cout << "Retrying..." << std::endl;
        udpPortScanner->scanPortRange(lowPort, highPort);
    }
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
}

PuzzleSolver::~PuzzleSolver() {}

void PuzzleSolver::printPorts() {
    udpPortScanner->displayOpenPorts();
}

void PuzzleSolver::solvePuzzleOne() {

    // Send a string "$group_6$" to the port and get more instructions

    std::string data0 = "$group_6$";
    char responseMessageBuffer[MAX_BUFFER];
    int destinationPort = udpPortScanner->getUdpClient()->getAddressPort();

    int bytesReceived = -1;
    int tries = 1;
    int maxTries = 5;
    bool unableToGetResponse = false;

    while (bytesReceived < 0) {
        memset(responseMessageBuffer, 0, sizeof(responseMessageBuffer));
        if (tries >= maxTries) {
            unableToGetResponse = true;
            break;
        }
        std::cout << "Trying to get a response from port " << destinationPort << " (tries: " << tries << ")..." << std::endl;
        udpPortScanner->getUdpClient()->send(data0.c_str(), data0.size());
        bytesReceived = udpPortScanner->getUdpClient()->receive(responseMessageBuffer, MAX_BUFFER);
        tries++;
    }

    if (unableToGetResponse) {
        std::cout << "Unable to reach port " << destinationPort << "..." << std::endl;
        return;
    }

    std::cout << "Port " << destinationPort << " responded with the following message:" << std::endl;
    std::cout << responseMessageBuffer << std::endl;

    std::cout << "Setting up an appropriate response..." << destinationPort << "..." << std::endl;

    /*
     * Raw socket setup and receive
     */

    /// Create a raw socket to send with

    int rawSendSocket;
    if ((rawSendSocket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
        std::cout << "Failed to create socket" << std::endl;
        exit(1);
    }

    char datagram[4096], *data1, *pseudogram;

    memset(datagram, 0, 4096);

    // IP header
    struct ip *iph = (struct ip *) datagram;

    // UDP header
    struct udphdr *uhdr = (struct udphdr *) (datagram + sizeof(struct ip));

    struct sockaddr_in sin;
    struct pseudo_header psh;

    // Data
    data1 = (datagram + sizeof(struct ip)) + sizeof(struct udphdr);
    strcpy(data1, "[udp packet with all the stuff i need to do]");

    // Address resolution

    sin.sin_family = AF_INET;
    sin.sin_port = htons(udpPortScanner->getUdpClient()->getAddressPort());
    sin.sin_addr.s_addr = inet_addr(udpPortScanner->getUdpClient()->getAddress().c_str());

    // Fill the IP header

    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + strlen(data1);
    iph->ip_id = htonl(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = INADDR_ANY;
    iph->ip_dst.s_addr = sin.sin_addr.s_addr;

    // Checksum

    iph->ip_sum = checkSum((unsigned short *) datagram, iph->ip_len);

    // UDP header

    uhdr->uh_sport = htons (65255);
    uhdr->uh_dport = htons (htons(udpPortScanner->getUdpClient()->getAddressPort()));
    uhdr->uh_ulen = htons(sizeof(struct udphdr) + strlen(data1));
    uhdr->uh_sum = 0;	//leave checksum 0 now, filled later by pseudo header

    psh.source_address = iph->ip_src.s_addr;
    psh.dest_address = iph->ip_dst.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + strlen(data1));

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data1);
    pseudogram = (char *)(malloc(psize));

    memcpy(pseudogram, (char *) &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header),uhdr,sizeof(struct udphdr) + strlen(data1));

    uhdr->uh_sum = checkSum( (unsigned short*) pseudogram , psize);

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt (rawSendSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        std::cout << "Error setting IP_HDRINCL" << std::endl;
        exit(1);
    }

    int bytesReceived1 = -1;
    int tries1 = 1;
    int maxTries1 = 5;
    bool unableToGetResponse1 = false;

    udpPortScanner->getUdpClient()->setPort(6969);

    while (bytesReceived1 < 0) {
        memset(responseMessageBuffer, 0, sizeof(responseMessageBuffer));
        if (tries1 >= maxTries1) {
            unableToGetResponse1 = true;
            break;
        }
        std::cout << "Trying to get a response from port " << destinationPort << " via raw packet (tries: " << tries1 << ")..." << std::endl;


        sendto (rawSendSocket, datagram, iph->ip_len , 0, (struct sockaddr *) &sin, sizeof (sin));

        bytesReceived1 = udpPortScanner->getUdpClient()->receive(responseMessageBuffer, MAX_BUFFER);
        tries1++;
    }

    if (unableToGetResponse1) {
        std::cout << "Unable to recieve whilst sending a raw udp packet via port " << destinationPort << "..." << std::endl;
        return;
    }

    std::cout << "--- Port " << destinationPort << " responded with the following message:" << std::endl;
    std::cout << responseMessageBuffer << std::endl;











    /*
    RawSocketClient client = RawSocketClient(destIpAddress);
    client.createSocket();
    client.setDestinationPort(port);
    client.createDatagramAndSend("10.1.19.34", "$group_6$");

    udpPortScanner->getUdpClient()->setPort(port);

    udpPortScanner->getUdpClient()->setReceiveTimeout(1000);
    */

    ///////// CREATE RAW SOCKET AND SEND //////

    /*
    int rawSendSocket = socket (AF_INET, SOCK_RAW, IPPROTO_UDP);

    if(rawSendSocket == -1)
    {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create socket, make sure you are running with root privileges.");
        exit(1);
    }

    int dest_port = 4026;
    int source_port = 51192;


    // Datagram to represent my package
    char datagram[4096], source_ip[32], *data, *pseudogram;

    memset(datagram, 0, 4096);

    // IP header
    struct ip *iph = (struct ip *) datagram;

    // UDP header
    struct udphdr *uhdr = (struct udphdr *) (datagram + sizeof(struct ip));

    struct sockaddr_in sin;
    struct pseudo_header psh;

    //Data
    data = (datagram + sizeof(struct ip)) + sizeof(struct udphdr);
    strcpy(data, "$group_6$");


    // address resolution
    strcpy(source_ip, "192.168.50.65");

    // destination
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dest_port);
    sin.sin_addr.s_addr = inet_addr ("130.208.242.120");


    // Fill the IP header
    iph->ip_hl = 5;   // version
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + strlen(data);
    iph->ip_id = htonl(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = inet_addr(source_ip);
    iph->ip_dst.s_addr = sin.sin_addr.s_addr;

    // Checksum
    iph->ip_sum = checkSum((unsigned short *) datagram, iph->ip_len);


    //UDP Header
    uhdr->uh_sport = htons (source_port);
    uhdr->uh_dport = htons (dest_port);
    uhdr->uh_ulen = htons(sizeof(struct udphdr) + strlen(data));
    uhdr->uh_sum = 0;	//leave checksum 0 now, filled later by pseudo header


    // Now the UDP checksum
    psh.source_address = inet_addr( source_ip );
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + strlen(data) );


    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
    pseudogram = (char *)(malloc(psize));

    memcpy(pseudogram, (char *) &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header),uhdr,sizeof(struct udphdr) + strlen(data));

    uhdr->uh_sum = checkSum( (unsigned short*) pseudogram , psize);

    // set timevalue for timeout
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt (rawSendSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        exit(0);
    }

    // send the packet
    if (sendto (rawSendSocket, datagram, iph->ip_len , 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
        perror("sendto failed");
    }
        //Data sent successfully
    else {

        printf ("Packet Sent. Length : %d \n" , iph->ip_len);

        int rcv_sock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        struct sockaddr_in my_address;
        my_address.sin_addr.s_addr = inet_addr("192.168.50.65");
        my_address.sin_family = AF_INET;
        my_address.sin_port = htons(source_port);


        socklen_t socklen = (socklen_t)sizeof(my_address);
        if(bind(rcv_sock, (struct sockaddr *) &my_address, socklen) < 0){
            perror("bind failed");
            exit(0);
        }

        if (setsockopt(rawSendSocket, SOL_SOCKET, SO_RCVTIMEO, &tv,sizeof(tv)) < 0) {
            perror("Error");
        }

        char msg[1024];
        memset(msg, 0, 1024);

        struct sockaddr_in recv_addr {};
        int recv_addr_size = sizeof(recv_addr);

        int bytesReceived = recv(rcv_sock, msg, sizeof(msg), 0);
        if(bytesReceived < 0) {
            printf("RECIEVE ERROR: %s\n ", strerror(errno));
            printf("port = %d\n address = %d\n\n", sin.sin_port, sin.sin_addr.s_addr);
        } else {
            printf("port number: %d\n", dest_port);
            printf("%s\n", msg);
            printf("checksum = ");
            // std::cout << std::hex << iph->ip_sum << std::endl;
            std::cout << bytesReceived << std::endl;
        }

        close( rawSendSocket );
        close(rcv_sock);
        printf("\n-- closed send socket --\n\n");

    }
    */

    //////// DONE DOING RAW SOCKET //////

    /*
    RawSocketClient client = RawSocketClient(destIpAddress);
    client.createSocket();
    client.setDestinationPort(port);
    client.createDatagramAndSend("192.168.50.65", "$group_6$");


    udpPortScanner->getUdpClient()->bindSocket();
    udpPortScanner->getUdpClient()->setPort(port);
    udpPortScanner->getUdpClient()->setReceiveTimeout(1000);

    char buffer2[MAX_BUFFER];
    int bytesReceived = udpPortScanner->getUdpClient()->receive(buffer2, MAX_BUFFER);
    std::cout << "DEBUG:" << std::endl;
    std::cout << "Port: " << udpPortScanner->getUdpClient()->getAddressPort() << std::endl;
    std::cout << "Buffer:" << std::endl;
    // hexdump(&buffer2, MAX_BUFFER);
    std::cout << buffer2 << std::endl;
    std::cout << "Bytes received:" << std::endl;
    std::cout << bytesReceived << std::endl;
    */

}

void PuzzleSolver::solvePuzzles() {

    // Go through the ports and send messages accordingly
    // TODO: Fixa villu þegar portin eru núll: sudo ./puzzlesolver 130.208.242.120 0 0 0 0
    for (int i = 0; i < udpPortScanner->getOpenPorts().size(); ++i) {
        std::cout << std::endl;
        char messageBuffer[MAX_BUFFER];
        memset(messageBuffer, 0, sizeof(messageBuffer));
        udpPortScanner->getUdpClient()->setPort(udpPortScanner->getOpenPorts().at(i));
        int destinationPort = udpPortScanner->getUdpClient()->getAddressPort();
        std::string destinationAddress = udpPortScanner->getUdpClient()->getAddress();
        std::cout << "Solving for " << destinationAddress << ":" << destinationPort << "..." << std::endl;

        udpPortScanner->getUdpClient()->setReceiveTimeout(500);

        int bytesReceived = -1;

        int tries = 1;
        int maxTries = 5;
        bool unableToGetResponse = false;
        while (bytesReceived < 0) {
            if (tries >= maxTries) {
                unableToGetResponse = true;
                break;
            }

            std::cout << "Trying to get a response from port " << destinationPort << " (tries: " << tries << ")..." << std::endl;
            memset(messageBuffer, 0, sizeof(messageBuffer));
            udpPortScanner->getUdpClient()->send(NULL, 0);
            bytesReceived = udpPortScanner->getUdpClient()->receive(messageBuffer, MAX_BUFFER);
            tries++;
        }

        if (unableToGetResponse) {
            std::cout << "Unable to reach port " << destinationPort << "..." << std::endl;
            continue;
        }

        std::cout << "Port " << destinationPort << " responded with the following message:" << std::endl;
        std::cout << messageBuffer << std::endl;

        std::cout << "Determining which phase is applicable for port " << destinationPort << "..." << std::endl;

        std::string message = std::string(messageBuffer);

        if (message.find("Send me a message") != std::string::npos) {
            std::cout << "Port " << destinationPort << " is the x phase" << std::endl;
            solvePuzzleOne();
        } else if (message.find("I am the oracle")!= std::string::npos) {
            std::cout << "Port " << destinationPort << " is the y phase" << std::endl;
        } else if (message.find("The dark side")!= std::string::npos) {
            std::cout << "Port " << destinationPort << " is the evil bit phase" << std::endl;
        } else if (message.find("My boss")!= std::string::npos) {
            std::cout << "Port " << destinationPort << " is the z phase" << std::endl;
        } else {
            std::cout << "Port " << destinationPort << " is the an unknown phase..." << std::endl;
        }


    }

    // solvePuzzleOne(udpPortScanner->getOpenPorts().at(0));
    ///////////////////////////////////////////////////////////////////////////////////////////
    /// Testing to send and listen for port 4026 which sould be the 0th open port           ///
    ///////////////////////////////////////////////////////////////////////////////////////////

    // int listenUdpSocket, sendRawSocket;

    // int destinationPort = udpPortScanner->getOpenPorts().at(0);
    // RawSocketClient client = RawSocketClient(destIpAddress);
    // client.createSocket();
    // client.setDestinationPort(destinationPort);
    // client.createDatagramAndSend("10.2.26.17", "$group_6$");

    // udpClient->setPort(destinationPort);

    // char buffer[MAX_BUFFER];
    // udpClient->receive(buffer, MAX_BUFFER);
    // std::cout << buffer << std::endl;
}