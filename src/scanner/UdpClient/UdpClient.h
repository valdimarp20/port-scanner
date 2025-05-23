#ifndef UDP_SOCKET_H
#define UDP_SOCKET_H

#include <netinet/in.h>
#include <sys/socket.h>

#include <string>

class UdpClient {
    private:
        const char *ipAddress;      // Host ip address
        int port;                   // Destination port
        int socket;                 // Socket for destination host
        sockaddr_in address;        // Address of the destination host
        socklen_t addressSize;      // Address length
        bool isPortSet = false;     // Set to true if port has been set
        bool isSocketOpen = false;  // Set to true if socket is not closed

        void buildSocket();
        void buildAddress();
        void buildAddressPort();
        void setAddressPort();

    public:
        UdpClient();
        UdpClient(const char *ipAddress);
        UdpClient(const char *ipAddress, int port);
        virtual ~UdpClient();
        int getAddressPort();
        void setPort(int port);
        void setReceiveTimeout(int milliseconds);
        void bindSocket();
        void closeSocket();
        void send(const void *data, int dataSize);
        int receive(const void *buffer, int bufferSize);
        int sendReceiveWithRetriesAndTimeout(const void *data, int dataSize, const void *buffer,
                                             int bufferSize, int maxTries, int milliseconds);
};

#endif  // UDP_SOCKET_H