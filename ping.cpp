#include <iostream>
#include <bits/stdc++.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <cstring>
#include <unistd.h>
#include <chrono>

using namespace std;
using namespace std::chrono;

void help() {
    cout << "Usage: ./icmpups" << " -d <destination ip>" << endl << endl;
    cout << "Also you can use: " << endl <<
         "-c <count of packages>" << endl <<
         "-d <destination ip>" << endl <<
         "-t <timeout in ms>" << endl <<
         "-rt <response_timeout>" << endl;
}

pid_t ppid = getppid();

void catch_ctrl_c(int signal);

void ping(char *ip, int count_of_packages, int timeout, int response_timeout);

void stat();

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
    int count_of_packages = 10;
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

        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--count") == 0) {
            count_of_packages = atoi(argv[i + 1]);
            i += 1;
        }

        if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--timeout") == 0) {
            timeout = atoi(argv[i + 1]);
            i += 1;
        }

        if (strcmp(argv[i], "-rt") == 0 || strcmp(argv[i], "--response_timeout") == 0) {
            response_timeout = atoi(argv[i + 1]);
            i += 1;
        }
    }

    signal(SIGINT, catch_ctrl_c);
    ping(ip, count_of_packages, timeout, response_timeout);

    return 0;
}

int sock;
int sent, received;

void ping(char *ip, int count_of_packages, int timeout, int response_timeout) {


    cout << "Ping stats for " << "\033[1;35m" << ip << "\033[0m" << endl << endl;

    struct sockaddr_in in_addr{};

    in_addr.sin_family = AF_INET;
    in_addr.sin_addr.s_addr = inet_addr(ip);
    in_addr.sin_port = htons(0);

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);

    if (sock < 0) {
        perror("socket error");
        return;
    }

    struct icmpHeader icmpPacket{};

    unsigned long int avg_ping = 0;

    for (int i = 0; i < count_of_packages; i++) {
        if (i != 0) {
            usleep(timeout * 1000);
        }

        icmpPacket.type = 8;
        icmpPacket.code = 0;
        icmpPacket.checksum = 0;
        icmpPacket.meta.echo.identifier = ppid;
        icmpPacket.meta.echo.sequence = i;
        icmpPacket.meta.echo.payload = 0b101101010110100101; // random binary data, doesnt matter
        icmpPacket.checksum = checksum(&icmpPacket, sizeof(icmpPacket));


        long int send_flag = sendto(sock, &icmpPacket, sizeof(icmpPacket), 0, (struct sockaddr *) &in_addr,
                                    socklen_t(sizeof(in_addr)));

        sent++;

        uint64_t ms_before = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();


        if (send_flag < 0) {
            perror("send error");
            return;
        }

        char buf[1024];

        auto *icmpResponseHeader = (struct icmpHeader *) buf;

        struct timeval tv;
        tv.tv_sec = response_timeout;
        tv.tv_usec = 0;

        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));


        int data_length_byte = recv(sock, icmpResponseHeader, sizeof(buf), 0);

        if(data_length_byte == -1) {
            cout << "\033[1;31m" << "Host unreachable or response timeout." << "\033[0m" << "   ";
            cout << "Sequence: " << "\033[1;35m" << i << "\033[0m" << "    ";
            cout << "Process id: " << "\033[1;35m" << ppid << "\033[0m" << endl;
            continue;
        }

        uint64_t ms_after = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();

        received++;

        cout << "Received " << "\033[1;35m" << data_length_byte << "\033[0m" << " bytes of data from " << ip << "    ";
        cout << "ICMP response type: " << "\033[1;35m" << unsigned(icmpResponseHeader->type) << "\033[0m" << "    ";
        cout << "ICMP response code: " << "\033[1;35m" << unsigned(icmpResponseHeader->code) << "\033[0m" << "    ";
        cout << "ICMP response checksum: " << "\033[1;35m" << icmpResponseHeader->checksum << "\033[0m" << "    ";

        uint64_t time = ms_after - ms_before;
        avg_ping += time;

        cout << "Time: " << "\033[1;35m" << time << "ms" << "\033[0m" << "    ";
        cout << "Sequence: " << "\033[1;35m" << i << "\033[0m" << "    ";
        cout << "Process id: " << "\033[1;35m" << ppid << "\033[0m" << endl;



    }

    avg_ping = avg_ping / count_of_packages;

    if (avg_ping < 5) {
        cout << "Your connection is good. Avg ping " << avg_ping << "ms" << endl;
    } else {
        cout << "Bad connection. Avg ping " << avg_ping << "ms" << endl;
    }
    stat();
}

void stat () {
    cout << endl << "Sent: " << "\033[1;35m" << sent << "\033[0m" << "   "
         << "Received: " << "\033[1;35m" << received << "\033[0m" << "    "
         << "Loss: " << "\033[1;35m" << sent - received << " (" << (sent * 100) / received << "%)" <<"\033[0m" << endl;
}

void catch_ctrl_c(int signal) {
    close(sock);
    stat();
    cout << endl << "\033[1;35m" << "Socket closed. Exiting..." << "\033[0m" << endl << endl;
    exit(signal);
}