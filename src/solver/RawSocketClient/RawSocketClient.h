#ifndef RAW_SOCKET_CLIENT_H
#define RAW_SOCKET_CLIENT_H

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>

struct pseudo_header {
        u_int32_t source_address;
        u_int32_t dest_address;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t udp_length;
};

class RawSocketClient {
    private:
        const char* destinationIpAddress;
        int destinationPort;
        sockaddr_in destinationAddress;
        socklen_t destinationAddressSize;

        int socket;

        void buildSocket();
        void setIncludeHeaderDataOption();

        void buildDestinationPort();
        void buildDestinationAddress();

        unsigned short calculateChecksum(unsigned short* buffer, int numBytes);

    public:
        RawSocketClient(const char* destinationIpAddress);
        virtual ~RawSocketClient();
        void createSocket();
        void setDestinationPort(int port);
        void createDatagramAndSend(const char* sourceIpAddress, const char* message);
};

#endif  // RAW_SOCKET_CLIENT_H