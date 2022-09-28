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
    if (isSocketOpen) {
        try {
            closeSocket();
        } catch (SocketException &exception) {
            std::cerr << exception.what() << std::endl;
        }
    }
}

/**
 * Get the port number stored in the destination address.
 *
 * @return Port found in the destination address.
 */
int UdpClient::getAddressPort() {
    int addressPort = ntohs(address.sin_port);
    return addressPort;
}

/**
 * Set the client destination port.
 *
 * @param port New destination port.
 */
void UdpClient::setPort(int port) {
    this->port = port;
    buildAddressPort();
    if (!isPortSet) {
        isPortSet = true;
    }
}

/**
 * Set the client receive timeout.
 *
 * @param milliseconds Time to wait for client receive operation.
 * @throws SocketException thrown if timeout could no be set.
 */
void UdpClient::setReceiveTimeout(int milliseconds) {
    timeval timeout;
    timeout.tv_sec = milliseconds / 1000;
    timeout.tv_usec = (milliseconds % 1000) * 1000;

    int isTimeoutSet =
        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (timeval *)&timeout, sizeof(timeout));
    if (isTimeoutSet < 0) {
        throw SocketException("Failed to set socket receive timeout");
    }
}

/**
 * Build the destination address structure.
 *
 * @throws SocketException thrown if address cold not set.
 */
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

/**
 * Build the destination address structure by setting the address port & address size.
 */
void UdpClient::buildAddressPort() {
    address.sin_port = htons(port);
    addressSize = sizeof(address);
}

/**
 * Build the destination UDP socket.
 *
 * @throws SocketException thrown if socket creation fails.
 */
void UdpClient::buildSocket() {
    socket = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (socket < 0) {
        throw SocketException(strerror(errno));
    } else {
        isSocketOpen = true;
    }
}

/**
 * Bind the destination socket to the destination address.
 *
 * @throws SocketException thrown if bind fails.
 */
void UdpClient::bindSocket() {
    int isBound = bind(socket, (struct sockaddr *)&address, (socklen_t)sizeof(address));
    if (isBound < 0) {
        throw SocketException(strerror(errno));
    }
}

/**
 * Close the socket associated with client.
 *
 * @throws SocketException thrown if socket could not be closed.
 */
void UdpClient::closeSocket() {
    int isClosed = close(socket);
    if (isClosed < 0) {
        throw SocketException(strerror(errno));
    } else {
        isSocketOpen = false;
    }
}

/**
 * Send data to the destination & wait for a response.
 * If no response is received within the timeout period, the operation is repeated until the retry
 * limit is reached and/or a response is received.
 *
 * @param *data Data to send.
 * @param dataSize Size of data in bytes.
 * @param *buffer Buffer for storing received data.
 * @param bufferSize Size of buffer in bytes.
 * @param maxTries Maximum number of times to retry.
 * @param milliseconds Timout duration for receiving.
 * @return The number of bytes received.
 */
int UdpClient::sendReceiveWithRetriesAndTimeout(const void *data, int dataSize, const void *buffer,
                                                int bufferSize, int maxTries, int milliseconds) {
    int tries = 0, bytesReceived = -1;
    try {
        setReceiveTimeout(milliseconds);
    } catch (SocketException &exception) {
        std::cerr << exception.what() << std::endl;
        return bytesReceived;
    }
    do {
        try {
            send(data, dataSize);
        } catch (SocketException &exception) {
            std::cerr << exception.what() << std::endl;
            tries++;
            continue;
        }
        bytesReceived = receive(buffer, bufferSize);
        tries++;
    } while (tries < maxTries && bytesReceived < 0);

    return bytesReceived;
}

/**
 * Send data to the destination.
 *
 * @param *data Data to send.
 * @param dataSize Size of data in bytes.
 * @throws SocketException thrown if a destination port has not been set.
 * @throws SocketException thrown if the send operation failed.
 */
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

/**
 * Receive data from the destination.
 *
 * @param *buffer Buffer for storing received data.
 * @param bufferSize Size of buffer in bytes.
 * @return The number of bytes received.
 */
int UdpClient::receive(const void *buffer, int bufferSize) {
    int bytesRead =
        recvfrom(socket, (void *)buffer, bufferSize, 0, (sockaddr *)&address, &addressSize);
    return bytesRead;
}
