#include "PuzzleSolver.h"

#include <iostream>
#include <vector>

#include "../../scanner/UdpClient/UdpClient.h"
#include "../../shared/SocketException.h"
#include "../RawSocketClient/RawSocketClient.h"

PuzzleSolver::PuzzleSolver() {
    this->ipAddress = "";
    this->udpClient = new UdpClient();
    this->udpPortScanner = new UdpPortScanner();
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



    while (udpPortScanner->getOpenPorts().size() != 4) {
        // TODO: Create an exception here
        std::cout << "Something went wrong, didn't get all four ports!" << std::endl;
        std::cout << "These ports are the open ports we found:" << std::endl;
        udpPortScanner->displayOpenPorts();
        udpPortScanner->scanPortRange(lowPort, highPort);
    }
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
    this->udpPortScanner->setOpenPorts({ port1, port2, port3, port4 });
}

PuzzleSolver::~PuzzleSolver() {
    delete udpClient;
    delete udpPortScanner;
}

void PuzzleSolver::printPorts() {
    udpPortScanner->displayOpenPorts();
}

void PuzzleSolver::solvePuzzles() {
    // Go through the ports and send messages accordingly
    /*
    for (int i = 0; i < udpPortScanner->getOpenPorts().size(); ++i) {
        std::cout << "Port " << udpPortScanner->getOpenPorts().at(i) << " is open." << std::endl;
    int port = udpPortScanner->getOpenPorts().at(i);
    }
    */

    ///////////////////////////////////////////////////////////////////////////////////////////
    /// Testing to send and listen for port 4026 which sould be the 0th open port           ///
    ///////////////////////////////////////////////////////////////////////////////////////////

    // int listenUdpSocket, sendRawSocket;

    int destinationPort = udpPortScanner->getOpenPorts().at(0);
    RawSocketClient client = RawSocketClient(ipAddress);
    client.createSocket();
    client.setDestinationPort(destinationPort);
    client.createDatagramAndSend("10.1.19.34", "$group_6$");



}