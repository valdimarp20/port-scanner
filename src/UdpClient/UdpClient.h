#ifndef UDP_SOCKET_H
#define UDP_SOCKET_H

#include <netinet/in.h>
#include <sys/socket.h>

class UdpClient {
    private:
        const char *ipAddress;   // Host ip address
        int port;                // Destination port
        bool isPortSet = false;  // Set to true if port has been set
        int socket;              // Socket for destination host
        sockaddr_in address;     // Address of the destination host
        socklen_t addressSize;   // Address length

        void buildSocket();
        void buildAddress();
        void buildAddressPort();
        void setAddressPort();

    public:
        UdpClient(const char *ipAddress);
        UdpClient(const char *ipAddress, int port);
        virtual ~UdpClient();
        int getAddressPort();
        void setPort(int port);
        void setReceiveTimeout(int milliseconds);
        int receive(const void *buffer, int bufferSize);
        void send(const void *data, int dataSize);
};

#endif  // UDP_SOCKET_H