#include "protocol_analysis.h"
#include "utils.h"
#include "globals.h"
#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

std::map<std::string, int> ipCount;
std::map<int, int> protocolCount;
std::map<std::string, std::chrono::system_clock::time_point> lastLogged;
const std::chrono::minutes logInterval(1); 

void analyzeIPHeader(const u_char* packet) {
    const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));

    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    // Konwersja adresów IP na czytelny format
    inet_ntop(AF_INET, &(ipHeader->ip_src), src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dst, INET_ADDRSTRLEN);

    std::cout << getCurrentTime() << ": IP Source: " << src <<" - "<<"IP Destination: " << dst << std::endl;
}

void detectAnomaly(const u_char* packet) {
    const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    char src[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_src), src, INET_ADDRSTRLEN);
    std::string srcIP(src);
    ipCount[srcIP]++;
    //////////////////////// funkcja testowa
       if (ipCount[srcIP] > 100 && ipCount[srcIP] < 1000) {
        logFile << getCurrentTime() <<": Liczba pakietów wieksza niz 100 : "<< srcIP << " - Ilosc: "<<ipCount[srcIP]<<std::endl;
    }
    ////////////////////////////////////////

    auto now = std::chrono::system_clock::now();
        if (ipCount[srcIP] > 1000 && (lastLogged.find(srcIP) == lastLogged.end() || now - lastLogged[srcIP] > logInterval)) {
                logFile << getCurrentTime() <<": Wykryto potencjalną anomalię: "<< "Ilosc: "<<ipCount[srcIP]<<" Adres: "<< srcIP << std::endl;
                std::cout << getCurrentTime() <<": Wykryto potencjalną anomalię: "<< "Ilosc: "<<ipCount[srcIP]<<" Adres: "<< srcIP << std::endl;
                lastLogged[srcIP] = now;
            }
}

void analyzeTCP(const u_char* payload, unsigned int size) {
    const struct tcphdr* tcpHeader = (struct tcphdr*)payload;

    // Pobieranie portów źródłowych i docelowych
    unsigned int srcPort = ntohs(tcpHeader->source);
    unsigned int dstPort = ntohs(tcpHeader->dest);

    // Pobieranie flag TCP
    unsigned int tcpFlags = tcpHeader->th_flags;

    std::cout << getCurrentTime() << ": TCP Source Port: " << srcPort << ", Destination Port: " << dstPort << " ";
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

    std::cout<< getCurrentTime() << ": UDP Source Port: " << srcPort << ", Destination Port: " << dstPort << std::endl;
}

void analyzeProtocol(const struct ip* ipHeader, const u_char* packet, unsigned int packetSize) {
    int protocol = ipHeader->ip_p;
    protocolCount[protocol]++;

    const u_char* payload = packet + sizeof(struct ether_header) + ipHeader->ip_hl * 4;

    switch(protocol) {
        case IPPROTO_TCP:
            analyzeTCP(payload, packetSize - ipHeader->ip_hl * 4);
            break;
        case IPPROTO_UDP:
            analyzeUDP(payload, packetSize - ipHeader->ip_hl * 4);
            break;
        case IPPROTO_ICMP:
            std::cout << getCurrentTime() << ": Protokół ICMP" << std::endl;
            break;
        case IPPROTO_SCTP:
            std::cout << getCurrentTime() << ": Protokół SCTP" << std::endl;
            break;
        default:
            std::cout << getCurrentTime()<< ": Inny protokół: " << static_cast<int>(protocol) << std::endl;
    }
}