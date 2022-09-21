#include "PuzzleSolver.h"

#include <iostream>
#include <vector>

#include "../../scanner/UdpClient/UdpClient.h"
#include "../../shared/SocketException.h"
#include "../RawSocketClient/RawSocketClient.h"

#define MAX_BUFFER 4096

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

    int lowPort = atoi("4000");
    int highPort = atoi("4100");
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

void PuzzleSolver::solvePuzzleOne(int port) {
    std::string message = "$group_6$";
    char buffer[MAX_BUFFER];

    UdpClient client = UdpClient(destIpAddress, port);

    client.send(message.c_str(), message.size());
    client.receive(buffer, MAX_BUFFER);

    std::cout << buffer << std::endl;
}

void PuzzleSolver::solvePuzzles() {
    // Go through the ports and send messages accordingly
    /*
    for (int i = 0; i < udpPortScanner->getOpenPorts().size(); ++i) {
        std::cout << "Port " << udpPortScanner->getOpenPorts().at(i) << " is open." << std::endl;
    int port = udpPortScanner->getOpenPorts().at(i);
    }
    */
    solvePuzzleOne(udpPortScanner->getOpenPorts().at(0));
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