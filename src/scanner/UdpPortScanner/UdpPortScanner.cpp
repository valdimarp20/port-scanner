#include "UdpPortScanner.h"

#include <iostream>
#include <vector>

#include "../../shared/SocketException.h"

UdpPortScanner::UdpPortScanner() {}

UdpPortScanner::UdpPortScanner(UdpClient *client) {
    this->client = client;
}

UdpPortScanner::~UdpPortScanner() {}

UdpClient *UdpPortScanner::getUdpClient() {
    return client;
}

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

bool UdpPortScanner::isPortOpen(int port, int tryAmount) {
    return scanPort(port, tryAmount) && port == client->getAddressPort();
}

bool UdpPortScanner::scanPort(int port, int tryAmount) {
    client->setPort(port);
    int bytesReceived = sendReceiveWithTries(tryAmount);

    return bytesReceived >= 0;
}

void UdpPortScanner::scanPortRange(int lowPort, int highPort, int tryAmount) {
    std::cout << "Scanning ..." << std::endl;

    openPorts.clear();
    for (int currentPort = lowPort; currentPort <= highPort; currentPort++) {
        if (isPortOpen(currentPort, tryAmount)) {
            openPorts.push_back(currentPort);
        }
    }
}

std::vector<int> &UdpPortScanner::getOpenPorts() {
    return this->openPorts;
}

void UdpPortScanner::setOpenPorts(std::vector<int> ports) {
    this->openPorts = ports;
}