// Includowanie wymaganych nagłówków i przestrzeni nazw
#include "protocol_analysis.h"
#include "utils/log_messages.h"
#include "utils/utils.h"
#include "globals.h"
#include <iostream>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

using namespace std;

// Definicja map do przechowywania statystyk
map<string, int> ipCount; // Liczba pakietów dla każdego adresu IP
map<int, int> protocolCount; // Liczba pakietów dla każdego protokołu
map<string, chrono::system_clock::time_point> lastLogged; // Ostatni czas zalogowania anomalii dla każdego IP
chrono::time_point<chrono::system_clock> lastLogTime = chrono::system_clock::now(); // Ostatni czas logowania
map<pair<unsigned int, unsigned int>, int> tcpStats; // Statystyki dla TCP (porty źródłowy i docelowy)
map<pair<unsigned int, unsigned int>, int> udpStats; // Statystyki dla UDP (porty źródłowy i docelowy)
map<int, int> icmpStats; // Statystyki dla ICMP
map<int, int> sctpStats; // Statystyki dla SCTP
map<int, int> unknownProtocol; // Globalna mapa do przechowywania statystyk dla nierozpoznanych protokołów
const chrono::minutes aggregationInterval(5); // Interwał czasowy dla agregacji danych

// Logowanie zagregowanych danych
void logAggregatedData() {
    static chrono::system_clock::time_point lastLogTime = chrono::system_clock::now(); // Inicjalizacja statycznego czasu ostatniego logowania
    auto now = chrono::system_clock::now(); // Pobranie aktualnego czasu
    // Obliczenie różnicy czasu
    auto elapsed = now - lastLogTime;
        if (elapsed >= aggregationInterval) { // Sprawdzenie czy minęła minuta od ostatniego logowania
            cout << SUMMARY_HEADER << endl; // Wyświetlenie nagłówka podsumowania
            cout << getCurrentTime() << AGGREGATED_STATS << endl; // Wyświetlenie czasu i informacji o zagregowanych statystykach
            // Pętle do wyświetlania zagregowanych danych dla każdego protokołu
            for (const auto& pair : tcpStats) { cout << TCP_LOG_MESSAGE << pair.first.first << PORT_DST << pair.first.second << IP_PACKET_COUNT_MESSAGE << pair.second << endl; }
            for (const auto& pair : udpStats) { cout << UDP_LOG_MESSAGE << pair.first.first << PORT_DST << pair.first.second << IP_PACKET_COUNT_MESSAGE << pair.second << endl; }
            for (const auto& pair : icmpStats) { cout << ICMP_LOG_MESSAGE << pair.first << IP_PACKET_COUNT_MESSAGE << pair.second << endl; }
            for (const auto& pair : sctpStats) { cout << SCTP_LOG_MESSAGE << pair.first << IP_PACKET_COUNT_MESSAGE << pair.second << endl; }
            for (const auto& pair : unknownProtocol) { cout << UNKNOWN_PROTOCOL_MESSAGE << pair.first << IP_PACKET_COUNT_MESSAGE << pair.second << endl;}
            cout << SUMMARY_HEADER << endl; // Wyświetlenie końcowego nagłówka podsumowania
            // Resetowanie statystyk
            tcpStats.clear();
            udpStats.clear();
            icmpStats.clear();
            sctpStats.clear();
            unknownProtocol.clear();
            lastLogTime = now; // Aktualizacja czasu ostatniego logowania
        }
}

// Konwertuje adres IP z formatu binarnego na tekstowy
string ipToString(const in_addr* addr) {
    // ipStr jest tablicą znaków, która przechowa tekstową reprezentację adresu IP.
    char ipStr[INET_ADDRSTRLEN]; 

    // Funkcja inet_ntop konwertuje adres IP z formatu binarnego (sieciowego) na tekstowy.
    // AF_INET oznacza, że używamy IPv4.
    // addr to wskaźnik na strukturę in_addr, która zawiera adres IP w formacie binarnym.
    // ipStr to miejsce docelowe, gdzie zostanie umieszczony tekstowy adres IP.
    // INET_ADDRSTRLEN to długość bufora, która jest wystarczająca na przechowanie maksymalnej długości adresu IPv4.
    inet_ntop(AF_INET, addr, ipStr, INET_ADDRSTRLEN);

    // Funkcja zwraca adres IP w postaci tekstowej jako obiekt string.
    return ipStr;
}

// Funkcja analizuje nagłówek IP w przechwyconym pakiecie sieciowym.
void analyzeIPHeader(const u_char* packet) {
    // Rzutowanie wskaźnika na pakiet do wskaźnika na strukturę nagłówka IP.
    // Pomija nagłówek Ethernetu poprzez dodanie do wskaźnika rozmiaru nagłówka Ethernetu.
    const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));

    // Konwersja adresów IP źródłowego i docelowego z formatu binarnego na tekstowy.
    string src = ipToString(&(ipHeader->ip_src));
    string dst = ipToString(&(ipHeader->ip_dst));
    
    // Inkrementacja liczników w mapie ipCount dla obu adresów IP.
    // Zlicza, ile razy każdy adres IP został zauważony.
    ipCount[src]++;
    ipCount[dst]++;
    
    // Pobieranie bieżącego czasu systemowego.
    auto now = chrono::system_clock::now();

    // Obliczanie, ile czasu minęło od ostatniego logowania statystyk.
    auto elapsed = chrono::duration_cast<chrono::minutes>(now - lastLogTime);
    if (elapsed.count() >= 1) {
        // Jeśli minęła co najmniej jedna minuta, loguje zebrane statystyki.
        cout << SUMMARY_HEADER << endl;
        cout << getCurrentTime() << NETWORK_TRAFFIC_SUMMARY << endl;
        
        // Iteracja przez mapę ipCount i wyświetlanie liczby pakietów dla każdego adresu IP.
        for (const auto& pair : ipCount) {
            cout << "IP: " << pair.first << IP_PACKET_COUNT_MESSAGE << pair.second << endl;
        }
        cout << SUMMARY_HEADER << endl;

        // Resetowanie liczników i aktualizacja czasu ostatniego logowania.
        ipCount.clear();
        lastLogTime = now;
    }
}


// Wykrywa anomalie w ruchu sieciowym, bazując na liczbie pakietów od określonego adresu IP
void detectAnomaly(const string& srcIP) {
    // Inkrementacja liczby pakietów dla danego adresu IP.
    // Jeśli adres IP nie istnieje w mapie ipCount, zostanie utworzony z wartością 1.
    ipCount[srcIP]++;

    // Pobranie bieżącego czasu.
    auto now = chrono::system_clock::now();

    // Sprawdzenie, czy liczba pakietów dla danego adresu IP przekracza próg anomalii (1000)
    // oraz czy minął określony interwał czasowy od ostatniego logowania anomalii dla tego adresu IP.
    if (ipCount[srcIP] > 1000 && (lastLogged.find(srcIP) == lastLogged.end() || now - lastLogged[srcIP] > aggregationInterval)) {
        // Logowanie do pliku, jeśli wykryto anomalię.
        // Zawiera bieżący czas, komunikat o wykrytej anomalii, liczbę pakietów i adres IP.
        logFile << getCurrentTime() << ANOMALY_DETECTED_MESSAGE << ipCount[srcIP] << ANOMALY_DETECTED_ADRESS << srcIP << endl;

        // Dodatkowe logowanie na konsolę dla użytkownika.
        cout << getCurrentTime() << ANOMALY_DETECTED_MESSAGE << ipCount[srcIP] << ANOMALY_DETECTED_ADRESS << srcIP << endl;

        // Aktualizacja czasu ostatniego logowania anomalii dla danego adresu IP.
        // Zapobiega to ciągłemu logowaniu tej samej anomalii w krótkim odstępie czasu.
        lastLogged[srcIP] = now;
    }
}


// Analizuje nagłówek TCP, w tym porty źródłowe i docelowe oraz flagi TCP
void analyzeTCP(const u_char* payload, unsigned int size) {
    // Wskazuje na nagłówek TCP w pakiecie, konwersja wskaźnika na odpowiedni typ.
    const struct tcphdr* tcpHeader = (struct tcphdr*)payload;

    // Konwersja numerów portów z formatu sieciowego na format hosta (big-endian na little-endian).
    unsigned int srcPort = ntohs(tcpHeader->source);
    unsigned int dstPort = ntohs(tcpHeader->dest);

    // Inkrementacja liczby pakietów w statystykach dla kombinacji portu źródłowego i docelowego.
    // Jeśli dany zestaw portów nie istnieje w mapie tcpStats, zostanie utworzony z wartością 1.
    tcpStats[{srcPort, dstPort}]++;
}

// Analizuje nagłówek UDP, w tym porty źródłowe i docelowe
void analyzeUDP(const u_char* payload, unsigned int size) {
    // Wskazuje na nagłówek UDP w pakiecie, konwersja wskaźnika na odpowiedni typ.
    const struct udphdr* udpHeader = (struct udphdr*)payload;

    // Konwersja numerów portów z formatu sieciowego na format hosta.
    unsigned int srcPort = ntohs(udpHeader->source);
    unsigned int dstPort = ntohs(udpHeader->dest);

    // Inkrementacja liczby pakietów w statystykach dla kombinacji portu źródłowego i docelowego.
    // Podobnie jak w TCP, jeśli dany zestaw portów nie istnieje w mapie udpStats, zostanie utworzony z wartością 1.
    udpStats[{srcPort, dstPort}]++;
}


// Wybiera odpowiednią funkcję analizującą na podstawie protokołu użytego w pakiecie IP
void analyzeProtocol(const struct ip* ipHeader, const u_char* packet, unsigned int packetSize) {
    // Pobiera wartość pola protokołu z nagłówka IP, aby zidentyfikować, jaki protokół jest używany (TCP, UDP, itp.)
    int protocol = ipHeader->ip_p;

    // Oblicza wskaźnik na dane (payload) w pakiecie, pomijając nagłówek Ethernet i IP
    const u_char* payload = packet + sizeof(struct ether_header) + ipHeader->ip_hl * 4;

    // Wybiera odpowiednią funkcję analizy w zależności od typu protokołu
    switch(protocol) {
        case IPPROTO_TCP:
            // Dla TCP: przekazuje payload do funkcji analyzeTCP
            analyzeTCP(payload, packetSize - ipHeader->ip_hl * 4);
            break;
        case IPPROTO_UDP:
            // Dla UDP: przekazuje payload do funkcji analyzeUDP
            analyzeUDP(payload, packetSize - ipHeader->ip_hl * 4);
            break;
        case IPPROTO_ICMP:
            // Dla ICMP: zwiększa licznik pakietów dla tego protokołu
            icmpStats[protocol]++;
            break;
        case IPPROTO_SCTP:
            // Dla SCTP: zwiększa licznik pakietów dla tego protokołu
            sctpStats[protocol]++;
            break;
        default:
            // Dla innych, nierozpoznanych protokołów
            if (protocol != 0) {
                unknownProtocol[protocol]++;
                // Jeśli protokół nie jest równy 0 (co oznaczałoby brak protokołu),
                // loguje informacje o napotkanym niezidentyfikowanym protokole
            }
    }
}
