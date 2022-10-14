#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cstring>
#include <bitset>
#include <unistd.h>
#include <chrono>

using namespace std;
using namespace std::chrono;

void help() {
    cout << "Usage: ./icmpups" << " -d <destination ip>" << endl << endl;
    cout << "Also you can use: " << endl <<
         "-c <count of packages>" << endl <<
         "-d <destination ip>" << endl <<
         "-t <timeout in ms>" << endl;
}

pid_t ppid = getppid();

void ping(char *ip, int count_of_packages, int timeout);

uint16_t checksum(const void *data, size_t len);

struct icmpHeader {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;

    union {
        struct {
            uint16_t identifier;
            uint16_t sequence;
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

    //char *count_of_packs =

    if (argc < 2) {
        help();
        return 0;
    }

    char *ip;
    int count_of_packages = 10;
    int timeout = 1000;

    for (int i = 0; i < argc; i++) {

        if (strcmp(argv[i], "-h") == 0) {
            help();
            return 0;
        }

        if (strcmp(argv[i], "-d") == 0) {
            ip = argv[i + 1];
            i += 1;
        }

        if (strcmp(argv[i], "-c") == 0) {
            count_of_packages = atoi(argv[i + 1]);
            i += 1;
        }

        if (strcmp(argv[i], "-t") == 0) {
            timeout = atoi(argv[i + 1]);
            i += 1;
        }

    }

    ping(ip, count_of_packages, timeout);

    return 0;
}

void ping(char *ip, int count_of_packages, int timeout) {
    struct sockaddr_in in_addr{};

    in_addr.sin_family = AF_INET;
    in_addr.sin_addr.s_addr = inet_addr(ip);
    in_addr.sin_port = htons(0);

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);

    if (sock < 0) {
        perror("socket error");
        return;
    }

    struct icmpHeader icmpPacket{};

    unsigned long int avg_ping = 0;

    for (int i = 0; i < count_of_packages; i++) {

        icmpPacket.type = 8;
        icmpPacket.code = 0;
        icmpPacket.checksum = 0;
        icmpPacket.meta.echo.identifier = ppid;
        icmpPacket.meta.echo.sequence = i;
        icmpPacket.checksum = checksum(&icmpPacket, sizeof(icmpPacket));


        long int send_flag = sendto(sock, &icmpPacket, sizeof(icmpPacket), 0, (struct sockaddr *) &in_addr,
                                    socklen_t(sizeof(in_addr)));

        uint64_t ms_before = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();


        if (send_flag < 0) {
            perror("send error");
            return;
        }

        char buf[1024];

        auto *icmpResponseHeader = (struct icmpHeader *) buf;

        long int data_length_byte = recv(sock, icmpResponseHeader, sizeof(buf), 0);

        uint64_t ms_after = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();

        cout << "Received " << data_length_byte << " bytes of data from " << ip << "    ";
        cout << "ICMP response type: " << unsigned(icmpResponseHeader->type) << "    ";
        cout << "ICMP response code: " << unsigned(icmpResponseHeader->code) << "    ";
        cout << "ICMP response checksum: " << icmpResponseHeader->checksum << "    ";

        if (unsigned(icmpResponseHeader->code) == 1) {
            cout << endl << "Host Unreachable" << endl;
            return;
        }

        uint64_t time = ms_after - ms_before;

        avg_ping += time;

        cout << "Time: " << time << "ms" << "    ";
        cout << "Sequence: " << i << "    ";
        cout << "Process id: " << ppid << endl;

        if (i != (count_of_packages - 1)) {
            usleep(timeout * 1000);
        }
    }

    avg_ping = avg_ping / count_of_packages;

    if (avg_ping < 5) {
        cout << "Your connection is good. Avg ping " << avg_ping << "ms" << endl;
    } else {
        cout << "Bad connection. Avg ping " << avg_ping << "ms" << endl;
    }

}