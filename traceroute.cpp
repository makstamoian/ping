#include <iostream>
#include <bits/stdc++.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <cstring>
#include <unistd.h>
#include <chrono>
#include <netinet/ip.h>

using namespace std;
using namespace std::chrono;

void help() {
    cout << "Usage: ./icmpups" << " -d <destination ip>" << endl << endl;
    cout << "Also you can use: " << endl <<
         "-h <hops>" << endl <<
         "-d <destination ip>" << endl <<
         "-rt <response_timeout>" << endl;
}

void catch_ctrl_c(int signal);

void traceroute(char *ip, int max_hops, int response_timeout);

uint16_t checksum(const void *data, size_t len);

struct icmpHeader {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;

    union {
        struct {
            uint16_t identifier;
            uint16_t sequence;
            uint64_t payload;
        } echo;

        struct ICMP_PACKET_POINTER_HEADER {
            uint8_t pointer;
        } pointer;

        struct ICMP_PACKET_REDIRECT_HEADER {
            uint32_t gatewayAddress;
        } redirect;
    } meta;
};

uint16_t checksum(const void *data, size_t len) {
    auto p = reinterpret_cast<const uint16_t *>(data);

    uint32_t sum = 0;

    if (len & 1) {
        sum = reinterpret_cast<const uint8_t *>(p)[len - 1];
    }

    len /= 2;

    while (len--) {
        sum += *p++;
        if (sum & 0xffff0000) {
            sum = (sum >> 16) + (sum & 0xffff);
        }
    }

    return static_cast<uint16_t>(~sum);
}


int main(int argc, char **argv) {
    cout << endl << endl;
    cout << "'####::'######::'##::::'##:'########::'##::::'##:'########:::'######::\n"
            ". ##::'##... ##: ###::'###: ##.... ##: ##:::: ##: ##.... ##:'##... ##:\n"
            ": ##:: ##:::..:: ####'####: ##:::: ##: ##:::: ##: ##:::: ##: ##:::..::\n"
            ": ##:: ##::::::: ## ### ##: ########:: ##:::: ##: ########::. ######::\n"
            ": ##:: ##::::::: ##. #: ##: ##.....::: ##:::: ##: ##.....::::..... ##:\n"
            ": ##:: ##::: ##: ##:.:: ##: ##:::::::: ##:::: ##: ##::::::::'##::: ##:\n"
            "'####:. ######:: ##:::: ##: ##::::::::. #######:: ##::::::::. ######::\n"
            "....:::......:::..:::::..::..::::::::::.......:::..::::::::::......:::";
    cout << endl << endl;
 
    if (argc < 2) {
        help();
        return 0;
    }

    char *ip;
    int max_hops = 30;
    int timeout = 1000;
    int response_timeout = 1;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            help();
            return 0;
        }

        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--destination") == 0) {
            ip = argv[i + 1];
            i += 1;
        }

        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--hops") == 0) {
            max_hops = atoi(argv[i + 1]);
            i += 1;
        }

        if (strcmp(argv[i], "-rt") == 0 || strcmp(argv[i], "--response_timeout") == 0) {
            response_timeout = atoi(argv[i + 1]);
            i += 1;
        }
    }

    signal(SIGINT, catch_ctrl_c);
    traceroute(ip, max_hops, response_timeout);

    return 0;
}

int sock;

void traceroute(char *ip, int max_hops, int response_timeout) {
    cout << "Traceroute to " << "\033[1;35m" << ip << "\033[0m" << endl;

    cout << "Max hops: " << "\033[1;35m" << max_hops << "\033[0m" << endl << endl;

    struct sockaddr_in in_addr{};

    in_addr.sin_family = AF_INET;
    in_addr.sin_addr.s_addr = inet_addr(ip);
    in_addr.sin_port = htons(0);

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sock < 0) {
        perror("socket error");
        return;
    }

    struct icmpHeader icmpPacket{};

    for (int i = 0; i < max_hops; i++) {

        icmpPacket.type = 8;
        icmpPacket.code = 0;
        icmpPacket.checksum = 0;
        icmpPacket.meta.echo.identifier = ppid;
        icmpPacket.meta.echo.sequence = i;
        icmpPacket.meta.echo.payload = 0b101101010110100101; // random binary data, doesnt matter
        icmpPacket.checksum = checksum(&icmpPacket, sizeof(icmpPacket));

        int ttl = i + 1;

        setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

        long int send_flag = sendto(sock, &icmpPacket, sizeof(icmpPacket), 0, (struct sockaddr *) &in_addr,
                                    socklen_t(sizeof(in_addr)));

        if (send_flag < 0) {
            perror("send error");
            return;
        }

        char buf[1024];

        auto *ipResponseHeader = (struct iphdr *) buf;

        struct timeval tv;
        tv.tv_sec = response_timeout;
        tv.tv_usec = 0;

        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));


        int data_length_byte = recv(sock, ipResponseHeader, sizeof(buf), 0);

        if(data_length_byte == -1) {
            cout << ttl << "\033[1;35m" << " * * *" << "\033[0m" << endl;
            continue;
        }

        struct sockaddr_in src_addr{};

        src_addr.sin_addr.s_addr = ipResponseHeader->saddr;

        cout << ttl << " " << "\033[1;35m" << inet_ntoa(src_addr.sin_addr) << "\033[0m" << endl;

        if(strcmp(inet_ntoa(src_addr.sin_addr), ip) == 0){
            cout << endl << "\033[1;35m" << ttl << "\033[0m" << " hops between you and " << ip << endl;
            break;
        }
    }
}

void catch_ctrl_c(int signal) {
    close(sock);
    cout << endl << "\033[1;35m" << "Socket closed. Exiting..." << "\033[0m" << endl << endl;
    exit(signal);
}
