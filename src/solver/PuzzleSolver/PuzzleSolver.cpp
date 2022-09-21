#include "PuzzleSolver.h"

#include <iostream>
#include <vector>

#include "../../scanner/UdpClient/UdpClient.h"
#include "../../shared/SocketException.h"

PuzzleSolver::PuzzleSolver() {
    this->ipAddress = "";
    this->udpClient = new UdpClient();
    this->udpPortScanner = new UdpPortScanner();
    this->port1 = 0;
    this->port2 = 0;
    this->port3 = 0;
    this->port4 = 0;
}

void PuzzleSolver::setPortsScan() {
    try {
        udpClient->setReceiveTimeout(50);
    } catch (SocketException &exception) {
        std::cerr << exception.what() << std::endl;
        // return ???
    }

    int lowPort = atoi("4000");
    int highPort = atoi("4100");
    udpPortScanner->scanPortRange(lowPort, highPort);
    std::vector<int> openPorts = udpPortScanner->getOpenPorts();

    if (openPorts.size() != 4) {
        // TODO: Create an exception here
        std::cout << "Something went wrong, didn't get all four ports!" << std::endl;
    }

    // std::cout << "Amount of open ports: " << openPorts.size() << std::endl;

    this->port1 = openPorts.at(0);
    this->port2 = openPorts.at(1);
    this->port3 = openPorts.at(2);
    this->port4 = openPorts.at(3);
}

PuzzleSolver::PuzzleSolver(const char *ipAddress) {
    this->ipAddress = ipAddress;
    this->udpClient = new UdpClient(ipAddress);
    this->udpPortScanner = new UdpPortScanner(udpClient);

    // If we are only given the ipAddress, we must find the open ports and assign them
    setPortsScan();
}

PuzzleSolver::PuzzleSolver(const char *ipAddress, int port1, int port2, int port3, int port4) {
    this->ipAddress = ipAddress;
    this->udpClient = new UdpClient(ipAddress);
    this->udpPortScanner = new UdpPortScanner(udpClient);
    this->port1 = port1;
    this->port2 = port2;
    this->port3 = port3;
    this->port4 = port4;
}

PuzzleSolver::~PuzzleSolver() {
    delete udpClient;
    delete udpPortScanner;
}

void PuzzleSolver::printPorts() {
    std::cout << port1 << " " << port2 << " " << port3 << " " << port4 << std::endl;
}

void PuzzleSolver::solvePuzzles() {
    // Go through the ports and send messages accordingly
}