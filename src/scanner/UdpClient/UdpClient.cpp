#include "UdpClient.h"

#include <arpa/inet.h>
#include <unistd.h>

#include <iostream>

#include "../../shared/SocketException.h"

UdpClient::UdpClient() {}

UdpClient::UdpClient(const char *ipAddress) {
    this->ipAddress = ipAddress;
    try {
        buildAddress();
        buildSocket();
    } catch (SocketException &exception) {
        std::cerr << exception.what() << std::endl;
        exit(1);
    }
}

UdpClient::UdpClient(const char *ipAddress, int port) : UdpClient(ipAddress) {
    setPort(port);
}

UdpClient::~UdpClient() {
    close(socket);
}

int UdpClient::getAddressPort() {
    int addressPort = ntohs(address.sin_port);
    return addressPort;
}

void UdpClient::setPort(int port) {
    this->port = port;
    buildAddressPort();
    if (!isPortSet) {
        isPortSet = true;
    }
}

// https://stackoverflow.com/questions/977684/how-can-i-express-10-milliseconds-using-timeval
void UdpClient::setReceiveTimeout(int milliseconds) {
    timeval timeout;
    timeout.tv_sec = milliseconds / 1000;
    timeout.tv_usec = (milliseconds % 1000) * 1000;

    int isTimeoutSet =
        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (timeval *)&timeout, sizeof(timeout));
    if (isTimeoutSet < 0) {
        throw SocketException("Failed to set socket receive timeout");
        // throw SocketException(strerror(errno));

    }
}

void UdpClient::buildAddress() {
    address.sin_family = AF_INET;
    int isAddressSet = inet_pton(AF_INET, ipAddress, &address.sin_addr);

    if (isAddressSet <= 0) {
        if (isAddressSet == 0) {
            throw SocketException("Invalid IPv4 address");
        } else {
            throw SocketException(strerror(errno));
        }
    }
}

void UdpClient::buildAddressPort() {
    address.sin_port = htons(port);
    addressSize = sizeof(address);
}

void UdpClient::buildSocket() {
    socket = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (socket < 0) {
        throw SocketException(strerror(errno));
    }
}

void UdpClient::send(const void *data, int dataSize) {
    int bytesSent = sendto(socket, data, dataSize, 0, (const sockaddr *)&address, addressSize);

    if (bytesSent < 0) {
        if (!isPortSet) {
            throw SocketException("Port has not been set");
        } else {
            throw SocketException(strerror(errno));
        }
    }
}

int UdpClient::receive(const void *buffer, int bufferSize) {
    int bytesRead =
        recvfrom(socket, (void *)buffer, bufferSize, 0, (sockaddr *)&address, &addressSize);
    return bytesRead;
}