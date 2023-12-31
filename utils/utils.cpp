#include "utils.h"
#include <chrono>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <sys/stat.h>

using namespace std;

/**
 * Pobiera bieżący czas systemowy i konwertuje go na strukturę tm.
 * 
 * return Struktura tm reprezentująca bieżący czas.
 */
tm getCurrentTimeTM() {
    auto now = chrono::system_clock::now(); // Pobiera bieżący czas systemowy
    auto in_time_t = std::chrono::system_clock::to_time_t(now); // Konwertuje czas na typ time_t
    return *localtime(&in_time_t); // Konwertuje time_t na strukturę tm
}

/**
 * Formatuje bieżący czas systemowy jako ciąg znaków.
 * 
 * return Sformatowany ciąg znaków reprezentujący bieżący czas.
 */
std::string getCurrentTime() {
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
long getFileSize(const std::string& filename) {
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
void checkAndRotateLogFile(int& index, std::ofstream& logFile) {
    const long MAX_LOG_SIZE = 1 * 1024 * 1024; // Maksymalny rozmiar pliku logów (1 MB)
    string currentFileName = getFileName(index);
    long fileSize = getFileSize(currentFileName);
    
    // Jeśli rozmiar pliku przekroczy maksymalny limit, tworzy nowy plik logów
    if (fileSize >= MAX_LOG_SIZE) {
        logFile.close(); // Zamyka bieżący plik logów
        logFile.open(getFileName(++index), ios::out); // Otwiera nowy plik logów z inkrementowanym indeksem
    }
}
