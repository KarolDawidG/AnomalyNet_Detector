#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <map>
#include <string>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

std::map<std::string, int> ipCount;
std::map<int, int> protocolCount;

std::string getCurrentTime() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X"); // Format YYYY-MM-DD HH:MM:SS
    return ss.str();
};

void analyzeIPHeader(const u_char* packet) {
    const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));

    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    // Konwersja adresów IP na czytelny format
    inet_ntop(AF_INET, &(ipHeader->ip_src), src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dst, INET_ADDRSTRLEN);

    //std::cout << "IP Source: " << src <<" - "<<"IP Destination: " << dst << std::endl;
}

void detectAnomaly(const u_char* packet) {
    const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    char src[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_src), src, INET_ADDRSTRLEN);

    std::string srcIP(src);

    // Zwiększanie licznika dla danego adresu IP
    ipCount[srcIP]++;

    // Prosty warunek do wykrywania anomalii
    if (ipCount[srcIP] > 100 && ipCount[srcIP] < 1000) {
        std::cout << getCurrentTime() <<": Liczba pakietów wieksza niz 100 : "<< srcIP << " - Ilosc: "<<ipCount[srcIP]<<std::endl;

    }

    if (ipCount[srcIP] > 1000 ) {
        std::cout << getCurrentTime() <<": Wykryto potencjalną anomalię: "<< "Ilosc: "<<ipCount[srcIP]<<" Adres: "<< srcIP << std::endl;
    }
}


void analyzeTCP(const u_char* payload, unsigned int size) {
    const struct tcphdr* tcpHeader = (struct tcphdr*)payload;

    // Pobieranie portów źródłowych i docelowych
    unsigned int srcPort = ntohs(tcpHeader->source);
    unsigned int dstPort = ntohs(tcpHeader->dest);

    // Pobieranie flag TCP
    unsigned int tcpFlags = tcpHeader->th_flags;

    std::cout << "TCP Source Port: " << srcPort << ", Destination Port: " << dstPort << std::endl;
    std::cout << "TCP Flags: ";
    if (tcpFlags & TH_SYN) std::cout << "SYN ";
    if (tcpFlags & TH_ACK) std::cout << "ACK ";
    if (tcpFlags & TH_RST) std::cout << "RST ";
    if (tcpFlags & TH_FIN) std::cout << "FIN ";
    if (tcpFlags & TH_URG) std::cout << "URG ";
    std::cout << std::endl;
}


void analyzeUDP(const u_char* payload, unsigned int size) {
    const struct udphdr* udpHeader = (struct udphdr*)payload;

    // Pobieranie portów źródłowych i docelowych
    unsigned int srcPort = ntohs(udpHeader->source);
    unsigned int dstPort = ntohs(udpHeader->dest);

    std::cout << "UDP Source Port: " << srcPort << ", Destination Port: " << dstPort << std::endl;
}


void analyzeProtocol(const struct ip* ipHeader, const u_char* packet, unsigned int packetSize) {
    int protocol = ipHeader->ip_p;
    protocolCount[protocol]++;

    const u_char* payload = packet + sizeof(struct ether_header) + ipHeader->ip_hl * 4;

    switch(protocol) {
        case IPPROTO_TCP:
            //std::cout << "Protokół TCP" << std::endl;
            analyzeTCP(payload, packetSize - ipHeader->ip_hl * 4);
            break;
        case IPPROTO_UDP:
            //std::cout << "Protokół UDP" << std::endl;
            analyzeUDP(payload, packetSize - ipHeader->ip_hl * 4);
            break;
        case IPPROTO_ICMP:
            std::cout << "Protokół ICMP" << std::endl;
            break;
        case IPPROTO_SCTP:
            std::cout << "Protokół SCTP" << std::endl;
            break;
        default:
            std::cout << "Inny protokół: " << static_cast<int>(protocol) << std::endl;
    }
}


void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));

    analyzeIPHeader(packet);
    detectAnomaly(packet);
    analyzeProtocol(ipHeader, packet, pkthdr->len);
}



int main() {
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Otworzenie urządzenia do przechwytywania
    descr = pcap_open_live("wlp2s0", BUFSIZ, 0, 1000, errbuf);

    if (descr == NULL) {
        std::cerr << "pcap_open_live() failed: " << errbuf << std::endl;
        return 1;
    }

    // Przechwytywanie pakietów
    if (pcap_loop(descr, -1, packetHandler, NULL) < 0) {
        std::cerr << "pcap_loop() failed: " << pcap_geterr(descr) << std::endl;
        return 1;
    }

    std::cout << "Capture complete" << std::endl;
    return 0;
}
