#include "UdpPortScanner.h"
#include <vector>

#include <iostream>

#include "../../shared/SocketException.h"

UdpPortScanner::UdpPortScanner() {}

UdpPortScanner::UdpPortScanner(UdpClient *client) {
    std::cout << "initializing udpportscanner" << std::endl;
    this->client = client;
}

UdpPortScanner::~UdpPortScanner() {}

void UdpPortScanner::displayOpenPorts() {
    if (openPorts.size() > 0) {
        std::cout << "OPEN PORTS" << std::endl;
        for (int port : openPorts) {
            std::cout << port << std::endl;
        }
    } else {
        std::cout << "NO PORTS OPEN" << std::endl;
    }
}

int UdpPortScanner::sendReceiveWithTries(int maxTries) {
    char buffer[1024];
    int tries = 0;
    int bytesReceived = -1;

    // Try to send & receive until max tries have been reached,
    // Or a the client receives data from the destination
    while (tries < maxTries && bytesReceived < 0) {
        try {
            client->send(NULL, 0);
        } catch (SocketException &exception) {
            break;
        }
        bytesReceived = client->receive(buffer, sizeof(buffer));
        tries++;
    }

    if (bytesReceived >= 0) {
        std::cout << "Received from " << client->getAddressPort() << " : " << buffer << std::endl;
        memset(buffer, 0, sizeof(buffer));
    }
    std::cout << "TRIED '" << tries << "' times for port " << client->getAddressPort() << std::endl;
    return bytesReceived;
}

bool UdpPortScanner::isPortOpen(int port) {
    return scanPort(port) && port == client->getAddressPort();
}

bool UdpPortScanner::scanPort(int port) {
    client->setPort(port);
    int bytesReceived = sendReceiveWithTries(3);

    return bytesReceived >= 0;
}

void UdpPortScanner::scanPortRange(int lowPort, int highPort) {
    std::cout << "Scanning ..." << std::endl;

    for (int currentPort = lowPort; currentPort <= highPort; currentPort++) {
        if (isPortOpen(currentPort)) {
            openPorts.push_back(currentPort);
        }
    }
}

std::vector<int> UdpPortScanner::getOpenPorts() {
    return this->openPorts;
}