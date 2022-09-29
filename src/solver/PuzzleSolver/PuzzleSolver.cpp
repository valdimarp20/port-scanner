#include "PuzzleSolver.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include <sys/socket.h>

#include <iostream>
#include <sstream>
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

/**
 * Solves the checksum port & gets the secret message.
 *
 * @param checksumPort Checksum puzzle port number.
 */
void PuzzleSolver::solveChecksumPort(PortMessagePair checksumPuzzle) {
    std::string completeSecretMessage;
    std::string secretMessage;
    std::tuple<std::string, std::string> checksumAndSourceIpAddress;

    std::cout << "Message from checksum port:" << std::endl
              << checksumPuzzle.message << std::endl
              << std::endl;

    checksumAndSourceIpAddress = getChecksumPortChecksumAndSourceIpAddress(checksumPuzzle.port);
    if (std::get<0>(checksumAndSourceIpAddress).length() > 0 &&
        std::get<1>(checksumAndSourceIpAddress).length() > 0) {
        std::cout << "==> Obtained the checksum '" << std::get<0>(checksumAndSourceIpAddress) << "'"
                  << std::endl;
        std::cout << "==> Obtained the source address '" << std::get<1>(checksumAndSourceIpAddress)
                  << "'" << std::endl;

        secretMessage =
            getChecksumPortSecret(checksumPuzzle.port, std::get<0>(checksumAndSourceIpAddress),
                                  std::get<1>(checksumAndSourceIpAddress));
    }

    // Parse secret message
    int quoteStartPosition = secretMessage.find("\"");
    int otherQuotePositions = secretMessage.find(".\"");
    completeSecretMessage =
        secretMessage.substr(quoteStartPosition + 1, otherQuotePositions - quoteStartPosition);

    if (secretMessage.find("Congratulations") != std::string::npos) {
        std::cout << "==> Found secret message " << std::endl << completeSecretMessage << std::endl;

    } else {
        std::cout << "==> Found message " << std::endl << secretMessage << std::endl;
    }
    secretPhrase = completeSecretMessage;
}

/**
 * Get the checksum & source ip address from the checksum puzzle port.
 *
 * @param checksumPort Checksum puzzle port number.
 * @return Tuple containing the obtained checksum & source ip address.
 */
std::tuple<std::string, std::string> PuzzleSolver::getChecksumPortChecksumAndSourceIpAddress(
    int checksumPort) {
    // Initialize
    char messageBuffer[MAX_BUFFER];
    int bytesReceived, exclamationPosition;
    std::string message;
    std::string checksum;
    std::string sourceIpAddress;
    UdpClient client = UdpClient(destIpAddress, checksumPort);
    std::tuple<std::string, std::string> checksumAndSourceIpAddress = std::make_tuple("", "");

    // Send group number #6
    int maxTries = 5;
    for (int tries = 0; tries < maxTries; tries++) {
        memset(messageBuffer, 0, sizeof(messageBuffer));  // Clear buffer

        std::cout << "==> Sending group number" << std::endl;
        bytesReceived =
            client.sendReceiveWithRetriesAndTimeout(groupNumber.c_str(), groupNumber.length(),
                                                    messageBuffer, sizeof(messageBuffer), 5, 1000);
        if (bytesReceived > 0) {
            message = std::string(messageBuffer);
            if (message.find("inform your TA") == std::string::npos) {
                std::cout << "==> Received a valid response" << std::endl;
                std::cout << message << std::endl << std::endl;
                break;
            } else {
                message = "";
                std::cout << "==> Received an invalid response" << std::endl;
                std::cout << "==> Trying again ..." << std::endl;
            }
        }
    }

    // Close client socket
    try {
        client.closeSocket();
    } catch (SocketException &exception) {
        std::cerr << exception.what() << std::endl;
    }

    // Parse message
    if (bytesReceived > 0 && message.length() > 0) {
        message = std::string(messageBuffer);

        // Get the checksum
        checksum = message.substr(message.find("0x") + 2, 4);

        // Get the ip address
        sourceIpAddress = message.substr(message.find("being ") + 6);
        exclamationPosition = sourceIpAddress.find("!");
        sourceIpAddress = sourceIpAddress.substr(0, exclamationPosition);

        // Insert checksum & ip address into tuple
        std::get<0>(checksumAndSourceIpAddress) = checksum;
        std::get<1>(checksumAndSourceIpAddress) = sourceIpAddress;
    }

    memset(messageBuffer, 0, sizeof(messageBuffer));  // Clear buffer
    return checksumAndSourceIpAddress;
}

/**
 * Gets the secret message from the checksum puzzle port.
 *
 * @param checksumPort Checksum puzzle port number.
 * @param checksum Checksum obtained from the checksum puzzle port.
 * @param sourceIpAddress Ip address obtained from the checksum puzzle port.
 * @return secret message
 */
std::string PuzzleSolver::getChecksumPortSecret(int checksumPort, std::string checksum,
                                                std::string sourceIpAddress) {
    // Initialize
    UdpClient client = UdpClient(destIpAddress, checksumPort);
    char message[MAX_BUFFER];
    std::string *messageBuffer;
    std::string secretMessage;
    int bytesSent, bytesReceived, checksumSize = 2;

    // Datagram to represent the packet
    char datagram[4096], *pseudogram;
    memset(datagram, 0, sizeof(datagram));  // Zero out packet buffer

    // IP header
    struct ip *iph = (struct ip *)datagram;

    // UDP header
    struct udphdr *udph = (struct udphdr *)(datagram + sizeof(struct ip));

    // Address resolution
    struct sockaddr_in destAddress;
    struct pseudo_header psh;

    destAddress.sin_family = AF_INET;
    destAddress.sin_port = htons(checksumPort);
    int isAddressSet = inet_pton(AF_INET, destIpAddress, &destAddress.sin_addr);

    // Fill in the IP header
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + checksumSize);
    iph->ip_id = htons(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = inet_addr(sourceIpAddress.c_str());
    iph->ip_dst.s_addr = destAddress.sin_addr.s_addr;

    // Fill in the UDP header
    udph->uh_sport = htons(RAW_COMMUNICATION_PORT);
    udph->uh_dport = htons(checksumPort);
    udph->uh_ulen = htons(sizeof(struct udphdr) + checksumSize);
    udph->uh_sum = htons((unsigned short)stoul(checksum, 0, 16));

    // Fill in the pseudo header
    psh.source_address = inet_addr(sourceIpAddress.c_str());
    psh.dest_address = destAddress.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + checksumSize);

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + checksumSize;
    pseudogram = new char[psize];

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr) + checksumSize);

    unsigned short initialChecksum = checkSum((unsigned short *)pseudogram, psize);
    messageBuffer = (std::string *)(datagram + sizeof(ip) + sizeof(struct udphdr));
    memcpy(messageBuffer, &initialChecksum, checksumSize);

    iph->ip_sum = htons(checkSum((unsigned short *)datagram, iph->ip_len));

    // Send the packet as a payload
    std::cout << "==> Sending packet in payload" << std::endl;
    bytesReceived = client.sendReceiveWithRetriesAndTimeout(datagram, htons(iph->ip_len), message,
                                                            sizeof(message), 5, 1000);
    // Close client socket
    try {
        client.closeSocket();
    } catch (SocketException &exception) {
        std::cerr << exception.what() << std::endl;
    }

    if (bytesReceived > 0) {
        std::cout << "==> Received a response" << std::endl;
        std::cout << message << std::endl << std::endl;
        secretMessage = message;
    }
    delete pseudogram;
    return secretMessage;
}

void PuzzleSolver::solveEvilBitPort(PortMessagePair messagePair) {
    std::cout << "This was the message we got:" << std::endl;
    std::cout << messagePair.message << std::endl;

    int rawSendSocket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (rawSendSocket < 0) {
        std::cerr << "Failed to create raw socket" << std::endl;
    }

    // Get local ip address
    struct sockaddr_in local_addr {};
    int local_addr_size = sizeof(local_addr);
    getsockname(rawSendSocket, (struct sockaddr *)&local_addr, (socklen_t *)&local_addr_size);

    char datagram[4096], *data1, *pseudogram;
    memset(datagram, 0, 4096);

    // IP header
    struct ip *iph = (struct ip *)datagram;

    // UDP header
    struct udphdr *uhdr = (struct udphdr *)(datagram + sizeof(struct ip));

    struct sockaddr_in sin;
    struct sockaddr_in destAddress;
    struct pseudo_header psh;

    // Data
    data1 = (datagram + sizeof(struct ip)) + sizeof(struct udphdr);
    strcpy(data1, "$group_6$");

    // Address resolution
    sin.sin_family = AF_INET;
    sin.sin_port = htons(messagePair.port);
    sin.sin_addr.s_addr = inet_addr(destIpAddress);

    destAddress.sin_family = AF_INET;
    destAddress.sin_port = htons(RAW_COMMUNICATION_PORT);
    destAddress.sin_addr.s_addr = INADDR_ANY;

    // Fill the IP header
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + strlen(data1);
    iph->ip_id = htons(54321);
    iph->ip_off = htons(0x80);  // Evil bit
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = 0;
    iph->ip_dst.s_addr = sin.sin_addr.s_addr;

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

    iph->ip_sum = checkSum((unsigned short *)datagram, iph->ip_len + 2);
    uhdr->uh_sum = checkSum((unsigned short *)pseudogram, psize + 2);

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

    // UdpClient client = UdpClient(inet_ntoa(local_addr.sin_addr), messagePair.port);
    UdpClient client = UdpClient(inet_ntoa(local_addr.sin_addr), RAW_COMMUNICATION_PORT);

    client.setReceiveTimeout(1000);
    client.bindSocket();

    char responseMessageBuffer[4096];
    while (bytesReceived1 < 0) {
        memset(responseMessageBuffer, 0, sizeof(responseMessageBuffer));
        if (tries1 >= maxTries1) {
            unableToGetResponse1 = true;
            break;
        }

        std::cout << "Trying to get a response from port " << messagePair.port
                  << " via raw packet (tries: " << tries1 << ")..." << std::endl;

        sendto(rawSendSocket, datagram, (sizeof(struct ip) + sizeof(struct udphdr) + strlen(data1)),
               0, (struct sockaddr *)&sin, sizeof(sin));

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

    secretPorts.push_back(intPort);

    std::cout << "Secret port 0: " << secretPorts[0] << ", Secret port 1: " << secretPorts[1]
              << std::endl;

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

void PuzzleSolver::solveOraclePort() {
    UdpClient client = UdpClient(destIpAddress, oraclePort);
    // std::string result = std::to_string(secretPorts[0]) + "," + std::to_string(secretPorts[1]);

    std::string result =
        std::to_string(secretPorts[0]) + "," +
        std::to_string(secretPorts[1]);  // as of now, port 4015 is the evil bit secret port
    client.setReceiveTimeout(500);

    std::cout << "Going to send this data to the oracle port:\n" << result << std::endl;

    int bytesReceived = -1;
    int tries = 0;
    int maxTries = 10;

    int bufferSize = 4096;
    char buffer[bufferSize];

    while (bytesReceived < 0 && tries < maxTries) {
        std::cout << "Trying to send to the oracle port (" << tries << ") tries..." << std::endl;
        client.send(result.c_str(), result.size());

        bytesReceived = client.receive(buffer, bufferSize);

        tries++;
    }

    if (bytesReceived < 0) {
        std::cout << "The server did not respond :(" << std::endl;
        return;
    }

    bytesReceived = -1;
    // Should get this response: 4015,4091,4091,4091,4015
    std::cout << "The server responded with these knock ports:" << std::endl;
    std::cout << buffer << std::endl;

    std::cout << "Sending to the server this secret phrase:" << std::endl;
    std::cout << secretPhrase << std::endl;

    std::string str = std::string(buffer);
    std::vector<int> knockPorts;

    std::stringstream ss(str);

    for (int i; ss >> i;) {
        knockPorts.push_back(i);
        if (ss.peek() == ',') ss.ignore();
    }

    // std::vector<int> knockPorts = {4015, 4091, 4091, 4091, 4015};

    for (int port : knockPorts) {
        client.setPort(port);
        memset(buffer, 0, sizeof(buffer));

        int tries = 0;
        int maxTries = 10;
        int noResponse = false;
        int bytesReceived = -1;

        while (bytesReceived < 0) {
            if (tries >= maxTries) {
                std::cout << "Unable to get response from port " << port << "... trying next port"
                          << std::endl;
                break;
            }

            client.send(secretPhrase.c_str(), secretPhrase.size());
            bytesReceived = client.receive(buffer, bufferSize);
            tries++;
        }

        if (bytesReceived > 0) std::cout << buffer << std::endl;
    }

    // client.setPort(4091);
    // client.send(secretPhrase.c_str(), secretPhrase.size());
    // client.send(secretPhrase.c_str(), secretPhrase.size());
    // client.send(secretPhrase.c_str(), secretPhrase.size());

    // client.setPort(4015);
    // client.send(secretPhrase.c_str(), secretPhrase.size());

    /*
    memset(buffer, 0, sizeof(buffer));
    client.receive(buffer, bufferSize);
    std::cout << "The server responded with (after knocking):\n" << buffer << std::endl;
    memset(buffer, 0, sizeof(buffer));
    client.receive(buffer, bufferSize);
    std::cout << buffer << std::endl;

    client.setPort(4091);
    memset(buffer, 0, sizeof(buffer));
    client.receive(buffer, bufferSize);
    std::cout << buffer << std::endl;

    memset(buffer, 0, sizeof(buffer));
    client.receive(buffer, bufferSize);
    std::cout << buffer << std::endl;

    memset(buffer, 0, sizeof(buffer));
    client.receive(buffer, bufferSize);
    std::cout << buffer << std::endl;
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
    for (PortMessagePair puzzle : portMessagePairs) {
        udpPortScanner->getUdpClient()->setPort(puzzle.port);

        if (puzzle.message.find("Send me a message") != std::string::npos) {
            std::cout << "------ SOLVING CHECKSUM PORT -----" << std::endl;
            solveChecksumPort(puzzle);

        } else if (puzzle.message.find("I am the oracle") != std::string::npos) {
            std::cout << "------ SETTING THE ORACLE PORT -----" << std::endl;
            std::cout << puzzle.message << std::endl;
            oraclePort = puzzle.port;
        } else if (puzzle.message.find("The dark side") != std::string::npos) {
            std::cout << "------ EVIL BIT PORT -----" << std::endl;
            solveEvilBitPort(puzzle);

        } else if (puzzle.message.find("My boss") != std::string::npos) {
            std::cout << "------ SOLVING SIMPLE PORT -----" << std::endl;
            solveSimplePort(puzzle.message);
            std::cout << "--------------------------------" << std::endl;
        }
    }

    if (secretPhrase.size() != 0 &&
        secretPorts.size() ==
            2) {  // change this to secretPorts.size() == 2 but for testing i am brute forceing
        std::cout << "------ SOLVING ORACLE PORT -----" << std::endl;
        solveOraclePort();
    } else {
        std::cout << "------ WE WERE NOT ABLE TO OBTAIN THE NECCECARY INFORMATION FOR THE ORACLE "
                     "PORT -----"
                  << std::endl;
        std::cout << "Please try to run the program again..." << std::endl;
    }
}