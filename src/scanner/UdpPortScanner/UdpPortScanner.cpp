#include "UdpPortScanner.h"

#include <iostream>
#include <vector>

#include "../../shared/SocketException.h"

UdpPortScanner::UdpPortScanner() {}

UdpPortScanner::UdpPortScanner(UdpClient *client) {
    this->client = client;
}

UdpPortScanner::~UdpPortScanner() {
    client->closeSocket();
}

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

void UdpPortScanner::scanPortRange(int lowPort, int highPort, int tryAmount) {
    openPorts.clear();

    for (int port = lowPort; port <= highPort; port++) {
        std::cout << "==> Scanning port '" << port << "' ..." << std::endl;
        if (isPortOpen(port, tryAmount)) {
            std::cout << "==> port " << port << "' is open !" << std::endl;
            openPorts.push_back(port);
        }
    }
}

bool UdpPortScanner::isPortOpen(int port, int tryAmount) {
    return scanPort(port, tryAmount) == client->getAddressPort();
}

/**
 * Check whether a given udp port is open.
 *
 * @param port Port to scan.
 * @param tryAmount Number of tries to scan the port.
 * @return port number if port is open, -1 otherwise.
 */
int UdpPortScanner::scanPort(int port, int tryAmount) {
    char buffer[1024];
    client->setPort(port);

    // Send & receive
    int bytesReceived =
        client->sendReceiveWithRetriesAndTimeout(NULL, 0, buffer, sizeof(buffer), tryAmount, 50);

    // Return the port if successful.
    if (bytesReceived >= 0) {
        return port;
    }
    return -1;
}

std::vector<int> &UdpPortScanner::getOpenPorts() {
    return this->openPorts;
}

void UdpPortScanner::setOpenPorts(std::vector<int> ports) {
    this->openPorts = ports;
}