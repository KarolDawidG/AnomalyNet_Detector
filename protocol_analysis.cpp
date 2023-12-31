#include "protocol_analysis.h"
#include "utils/log_messages.h"
#include "utils.h"
#include "globals.h"
#include <iostream>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

using namespace std;

map<string, int> ipCount;
map<int, int> protocolCount;
map<string, chrono::system_clock::time_point> lastLogged;
const chrono::minutes logInterval(1);
chrono::time_point<chrono::system_clock> lastLogTime = chrono::system_clock::now();
map<pair<unsigned int, unsigned int>, int> tcpStats;
map<pair<unsigned int, unsigned int>, int> udpStats;
map<int, int> icmpStats;
map<int, int> sctpStats;

// Logowanie zagregowanych danych
void logAggregatedData() {

    static chrono::system_clock::time_point lastLogTime = chrono::system_clock::now();
    auto now = chrono::system_clock::now();
    auto elapsed = chrono::duration_cast<chrono::minutes>(now - lastLogTime);

    if (elapsed.count() >= 1) {
        std::cout << SUMMARY_HEADER << endl;
        std::cout << getCurrentTime() << AGGREGATED_STATS << endl;
        for (const auto& pair : tcpStats) {         // Logowanie statystyk TCP
            cout << TCP_LOG_MESSAGE << pair.first.first << PORT_DST << pair.first.second << IP_PACKET_COUNT_MESSAGE << pair.second << endl;
        }
        for (const auto& pair : udpStats) {         // Logowanie statystyk UDP
            cout << UDP_LOG_MESSAGE << pair.first.first << PORT_DST << pair.first.second << IP_PACKET_COUNT_MESSAGE << pair.second << endl;
        }
        for (const auto& pair : icmpStats) {        // Logowanie statystyk ICMP
            cout << ICMP_LOG_MESSAGE << pair.first << IP_PACKET_COUNT_MESSAGE << pair.second << endl;
        }
        for (const auto& pair : sctpStats) {        // Logowanie statystyk SCTP
            cout << SCTP_LOG_MESSAGE << pair.first << IP_PACKET_COUNT_MESSAGE << pair.second << endl;
        }
        cout << SUMMARY_HEADER << endl;
        tcpStats.clear();       // Resetowanie statystyk
        udpStats.clear();
        icmpStats.clear();
        sctpStats.clear();
        lastLogTime = now;
    }
}

// Konwertuje adres IP z formatu binarnego na tekstowy
string ipToString(const in_addr* addr) {
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, addr, ipStr, INET_ADDRSTRLEN);
    return ipStr;
}

void analyzeIPHeader(const u_char* packet) {
    const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    string src = ipToString(&(ipHeader->ip_src));
    string dst = ipToString(&(ipHeader->ip_dst));
    
    ipCount[src]++;                                // Aktualizacja statystyk dla adresów IP
    ipCount[dst]++;
    
    auto now = chrono::system_clock::now();        // Sprawdzenie, czy minęła minuta od ostatniego logowania
    auto elapsed = chrono::duration_cast<chrono::minutes>(now - lastLogTime);
    if (elapsed.count() >= 1) {
        cout << SUMMARY_HEADER << endl;
        cout << getCurrentTime() << NETWORK_TRAFFIC_SUMMARY << endl;
        for (const auto& pair : ipCount) {
            cout << "IP: " << pair.first << IP_PACKET_COUNT_MESSAGE << pair.second << endl;
        }
        cout << SUMMARY_HEADER << endl;
        ipCount.clear();          // Resetowanie liczników i aktualizacja czasu ostatniego logowania
        lastLogTime = now;
    }
}


// Wykrywa anomalie w ruchu sieciowym, bazując na liczbie pakietów od określonego adresu IP
void detectAnomaly(const string& srcIP) {
    ipCount[srcIP]++;
    auto now = chrono::system_clock::now();
    if (ipCount[srcIP] > 1000 && (lastLogged.find(srcIP) == lastLogged.end() || now - lastLogged[srcIP] > logInterval)) {
        logFile << getCurrentTime() << ANOMALY_DETECTED_MESSAGE << ipCount[srcIP] << ANOMALY_DETECTED_ADRESS << srcIP << endl;
        cout << getCurrentTime() << ANOMALY_DETECTED_MESSAGE << ipCount[srcIP] << ANOMALY_DETECTED_ADRESS << srcIP << endl;
        lastLogged[srcIP] = now;
    }
}

// Analizuje nagłówek TCP, w tym porty źródłowe i docelowe oraz flagi TCP
void analyzeTCP(const u_char* payload, unsigned int size) {
    const struct tcphdr* tcpHeader = (struct tcphdr*)payload;
    unsigned int srcPort = ntohs(tcpHeader->source);
    unsigned int dstPort = ntohs(tcpHeader->dest);
    tcpStats[{srcPort, dstPort}]++;
}

// Analizuje nagłówek UDP, w tym porty źródłowe i docelowe
void analyzeUDP(const u_char* payload, unsigned int size) {
    const struct udphdr* udpHeader = (struct udphdr*)payload;
    unsigned int srcPort = ntohs(udpHeader->source);
    unsigned int dstPort = ntohs(udpHeader->dest);
    udpStats[{srcPort, dstPort}]++;
}

// Wybiera odpowiednią funkcję analizującą na podstawie protokołu użytego w pakiecie IP
void analyzeProtocol(const struct ip* ipHeader, const u_char* packet, unsigned int packetSize) {
    int protocol = ipHeader->ip_p;
    const u_char* payload = packet + sizeof(struct ether_header) + ipHeader->ip_hl * 4;
    switch(protocol) {
        case IPPROTO_TCP:
            analyzeTCP(payload, packetSize - ipHeader->ip_hl * 4);
            break;
        case IPPROTO_UDP:
            analyzeUDP(payload, packetSize - ipHeader->ip_hl * 4);
            break;
        case IPPROTO_ICMP:
            icmpStats[protocol]++;
            break;
        case IPPROTO_SCTP:
            sctpStats[protocol]++;
            break;
        default:
            if (protocol != 0){
                cout << getCurrentTime() << UNKNOWN_PROTOCOL_MESSAGE << static_cast<int>(protocol) << ")" << endl;
            }
            
    }
}
