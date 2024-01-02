#include "utils.h"
#include <chrono>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <sys/stat.h>
#include <fstream>
#include <iostream>
#include <regex>
#include <string>

using namespace std;

/**
 * Pobiera bieżący czas systemowy i konwertuje go na strukturę tm.
 * 
 * return Struktura tm reprezentująca bieżący czas.
 */
tm getCurrentTimeTM() {
    auto now = chrono::system_clock::now(); // Pobiera bieżący czas systemowy
    auto in_time_t = chrono::system_clock::to_time_t(now); // Konwertuje czas na typ time_t
    return *localtime(&in_time_t); // Konwertuje time_t na strukturę tm
}

/**
 * Formatuje bieżący czas systemowy jako ciąg znaków.
 * 
 * return Sformatowany ciąg znaków reprezentujący bieżący czas.
 */
string getCurrentTime() {
    tm bt = getCurrentTimeTM(); // Pobiera bieżący czas jako strukturę tm
    stringstream ss;
    ss << put_time(&bt, "%Y-%m-%d %X"); // Formatuje czas do formatu "YYYY-MM-DD HH:MM:SS"
    return ss.str();
}

/**
 * Generuje nazwę pliku na podstawie bieżącej daty i indeksu.
 * 
 * param index Indeks używany do tworzenia unikalnej nazwy pliku.
 * return Nazwa pliku z datą i indeksem.
 */
string getFileName(int index) {
    tm bt = getCurrentTimeTM(); // Pobiera bieżący czas jako strukturę tm
    char dateStr[100];
    strftime(dateStr, sizeof(dateStr), "%d-%m-%Y", &bt); // Formatuje datę do formatu "DD-MM-YYYY"

    ostringstream oss;
    oss << "logs/anomalyDetector-" << dateStr; // Dodaje ścieżkę 'logs/' przed nazwą pliku
    if (index > 0) {
        oss << "-" << index; // Dodaje indeks do nazwy pliku, jeśli jest większy niż 0
    }
    oss << ".txt";
    
    return oss.str();
}


/**
 * Zwraca rozmiar pliku.
 * 
 * param filename Nazwa pliku, którego rozmiar ma zostać sprawdzony.
 * return Rozmiar pliku w bajtach, lub -1 w przypadku błędu.
 */
long getFileSize(const string& filename) {
    struct stat stat_buf;
    int rc = stat(filename.c_str(), &stat_buf); // Pobiera informacje o pliku
    return rc == 0 ? stat_buf.st_size : -1; // Zwraca rozmiar pliku, lub -1 jeśli wystąpi błąd
}

/**
 * Sprawdza rozmiar bieżącego pliku logów i tworzy nowy plik, jeśli rozmiar przekroczy ustalony limit.
 * 
 * param index Referencja do indeksu bieżącego pliku logów.
 * param logFile Referencja do strumienia pliku logów.
 */
void checkAndRotateLogFile(int& index, ofstream& logFile) {
    const long MAX_LOG_SIZE = 1 * 512 * 512; // Maksymalny rozmiar pliku logów (256 kB)
    string currentFileName = getFileName(index);
    long fileSize = getFileSize(currentFileName);
    
    // Jeśli rozmiar pliku przekroczy maksymalny limit, tworzy nowy plik logów
    if (fileSize >= MAX_LOG_SIZE) {
        logFile.close(); // Zamyka bieżący plik logów
        logFile.open(getFileName(++index), ios::out); // Otwiera nowy plik logów z inkrementowanym indeksem
    }
}

/**
 * Analizuje logi i generuje raport.
 *
 * param logFileName Nazwa pliku logów.
 * return Nazwa pliku raportu.
 */
string generateReport(const string& logFileName) {
    ifstream logFile(logFileName);
    if (!logFile.is_open()) {
        cerr << "Nie można otworzyć pliku logów: " << logFileName << endl;
        return "";
    }

    string reportFileName = "reports/report.txt";
    ofstream reportFile(reportFileName);

    if (!reportFile.is_open()) {
        cerr << "Nie można utworzyć pliku raportu: " << reportFileName << endl;
        return "";
    }

    // Mapy do przechowywania statystyk
    map<string, int> ipAnomaliesCount;
    map<string, int> ipPacketCount;
    map<string, int> tcpPortStats;
    map<int, int> unidentifiedProtocolStats;

    string line;
    regex anomalyPattern(R"(Wykryto potencjalną anomalię: Ilość: (\d+) Adres: (\S+))");
    regex ipPacketPattern(R"(IP: (\S+) - Liczba pakietów: (\d+))");
    regex tcpPortPattern(R"(TCP - Port Src: (\d+), Port Dst: (\d+) - Liczba pakietów: (\d+))");
    regex protocolPattern(R"(Niezidentyfikowany protokół ID: (\d+) - Liczba pakietów: (\d+))");

    smatch match;
    while (getline(logFile, line)) {
        if (regex_search(line, match, anomalyPattern)) {
            ipAnomaliesCount[match[2]] += stoi(match[1]);
        } else if (regex_search(line, match, ipPacketPattern)) {
            ipPacketCount[match[1]] += stoi(match[2]);
        } else if (regex_search(line, match, tcpPortPattern)) {
            string portKey = "Src: " + match[1].str() + ", Dst: " + match[2].str();
            tcpPortStats[portKey] += stoi(match[3].str());
        } else if (regex_search(line, match, protocolPattern)) {
            unidentifiedProtocolStats[stoi(match[1])] += stoi(match[2]);
        }
    }

    // Zapis statystyk do pliku raportu
    reportFile << "Raport - Statystyki Anomalii IP" << endl;
    for (const auto& pair : ipAnomaliesCount) {
        reportFile << "IP: " << pair.first << " - Anomalie: " << pair.second << endl;
    }

    reportFile << "\nRaport - Liczba Pakietów na IP" << endl;
    for (const auto& pair : ipPacketCount) {
        reportFile << "IP: " << pair.first << " - Liczba pakietów: " << pair.second << endl;
    }

    reportFile << "\nRaport - Statystyki Portów TCP" << endl;
    for (const auto& pair : tcpPortStats) {
        reportFile << "Porty " << pair.first << " - Liczba pakietów: " << pair.second << endl;
    }

    reportFile << "\nRaport - Niezidentyfikowane Protokoły" << endl;
    for (const auto& pair : unidentifiedProtocolStats) {
        reportFile << "Protokół ID: " << pair.first << " - Liczba pakietów: " << pair.second << endl;
    }

    logFile.close();
    reportFile.close();
    return reportFileName;
}
