#include "UdpPortScanner.h"

#include <iostream>

#include "../UdpClient/SocketException.h"

UdpPortScanner::UdpPortScanner(UdpClient *client) {
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

bool UdpPortScanner::isPortOpen(int port) {
    char buffer[1024];

    client->setPort(port);
    try {
        client->send(NULL, 0);
    } catch (SocketException &exception) {
        return false;
    }

    int bytesReceived = client->receive(buffer, sizeof(buffer));
    return bytesReceived > 0;
}

void UdpPortScanner::scanPortRange(int lowPort, int highPort) {
    for (int currentPort = lowPort; currentPort <= highPort; currentPort++) {
        if (isPortOpen(currentPort)) {
            openPorts.push_back(currentPort);
        }
    }
}