#include "protocol_analysis.h"
#include "utils.h"
#include "globals.h"
#include <iostream>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>  // Dla struktur ip, iphdr
#include <netinet/tcp.h> // Dla struktur tcphdr
#include <netinet/udp.h> // Dla struktur udphdr

// Mapy do przechowywania liczby pakietów od poszczególnych IP oraz protokołów
std::map<std::string, int> ipCount;
std::map<int, int> protocolCount;
// Rejestrowanie czasu ostatniego zalogowania anomalii dla każdego IP
std::map<std::string, std::chrono::system_clock::time_point> lastLogged;
// Interwał czasowy, po którym ponownie rejestrowana jest anomalia od tego samego IP
const std::chrono::minutes logInterval(1);

std::chrono::time_point<std::chrono::system_clock> lastLogTime = std::chrono::system_clock::now();


// Konwertuje adres IP z formatu binarnego na tekstowy
std::string ipToString(const in_addr* addr) {
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, addr, ipStr, INET_ADDRSTRLEN);
    return ipStr;
}

void analyzeIPHeader(const u_char* packet) {
    const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    
    // Konwersja adresów IP na postać tekstową
    std::string src = ipToString(&(ipHeader->ip_src));
    std::string dst = ipToString(&(ipHeader->ip_dst));
    
    // Aktualizacja statystyk dla adresów IP
    ipCount[src]++;
    ipCount[dst]++;
    
     // Sprawdzenie, czy minęła minuta od ostatniego logowania
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - lastLogTime);
    if (elapsed.count() >= 1) {
        // Logowanie statystyk
        for (const auto& pair : ipCount) {
            std::cout <<getCurrentTime() << ": IP: " << pair.first << ", Liczba pakietów: " << pair.second << std::endl;
        }

        // Resetowanie liczników i aktualizacja czasu ostatniego logowania
        ipCount.clear();
        lastLogTime = now;
    }
    
}


// Wykrywa anomalie w ruchu sieciowym, bazując na liczbie pakietów od określonego adresu IP
void detectAnomaly(const std::string& srcIP) {
    ipCount[srcIP]++;
    auto now = std::chrono::system_clock::now();
    if (ipCount[srcIP] > 1000 && (lastLogged.find(srcIP) == lastLogged.end() || now - lastLogged[srcIP] > logInterval)) {
        logFile << getCurrentTime() << ": Wykryto potencjalną anomalię: Ilość: " << ipCount[srcIP] << " Adres: " << srcIP << std::endl;
        std::cout << getCurrentTime() << ": Wykryto potencjalną anomalię: Ilość: " << ipCount[srcIP] << " Adres: " << srcIP << std::endl;
        lastLogged[srcIP] = now;
    }
}

// Analizuje nagłówek TCP, w tym porty źródłowe i docelowe oraz flagi TCP
void analyzeTCP(const u_char* payload, unsigned int size) {
    const struct tcphdr* tcpHeader = (struct tcphdr*)payload;
    unsigned int srcPort = ntohs(tcpHeader->source);
    unsigned int dstPort = ntohs(tcpHeader->dest);
    unsigned int tcpFlags = tcpHeader->th_flags;
    std::cout << getCurrentTime() << ": TCP Source Port: " << srcPort << ", Destination Port: " << dstPort << " ";
    if (tcpFlags & TH_SYN) std::cout << "SYN ";
    if (tcpFlags & TH_ACK) std::cout << "ACK ";
    if (tcpFlags & TH_RST) std::cout << "RST ";
    if (tcpFlags & TH_FIN) std::cout << "FIN ";
    if (tcpFlags & TH_URG) std::cout << "URG ";
    std::cout << std::endl;
}

// Analizuje nagłówek UDP, w tym porty źródłowe i docelowe
void analyzeUDP(const u_char* payload, unsigned int size) {
    const struct udphdr* udpHeader = (struct udphdr*)payload;
    unsigned int srcPort = ntohs(udpHeader->source);
    unsigned int dstPort = ntohs(udpHeader->dest);
    std::cout << getCurrentTime() << ": UDP Source Port: " << srcPort << ", Destination Port: " << dstPort << std::endl;
}

// Wybiera odpowiednią funkcję analizującą na podstawie protokołu użytego w pakiecie IP
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
            std::cout << getCurrentTime() << ": Inny protokół: " << static_cast<int>(protocol) << std::endl;
    }
}
