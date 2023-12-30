#!/bin/bash

output="Analyzer"
source_files="main.cpp utils.cpp protocol_analysis.cpp"
log_file="analyzer.log"
find_latest_log_file() {
    ls -Art anomalyDetector-*.txt 2>/dev/null | tail -n 1
}



# Sprawdzenie, czy g++ i pcap są zainstalowane
if ! command -v g++ &> /dev/null || ! ldconfig -p | grep -q libpcap; then
    echo "Nie znaleziono wymaganych narzędzi (g++ lub libpcap)."
    exit 1
fi

# Kompilacja programu
g++ $source_files -o $output -lpcap

# Sprawdzenie, czy kompilacja się powiodła
if [ $? -ne 0 ]; then
    echo "Kompilacja nie powiodła się."
    exit 1
fi

# Nadanie uprawnień do przechwytywania pakietów (opcjonalne, wymaga sudo)
sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' $output

# Menu wyboru
echo "Wybierz opcję uruchomienia programu:"
echo "1) Uruchom w tle i zapisz logi do pliku."
echo "2) Uruchom w terminalu."
echo "3) Wyswietl podejrzane adresy IP"
echo "4) Zakoncz dzialanie programu"
read -p "Wybór: " choice

case $choice in
    1)
        # Uruchomienie programu w tle i zapis logów
        ./$output >> $log_file 2>&1 &
        clear
        echo "Program uruchomiony w tle, PID: $!"
        echo $! > program.pid   #plik z PID programu
        exec $0 # Uruchomienie skryptu ponownie
        ;;
    2)
        # Uruchomienie programu w terminalu
        ./$output
        ;;
    3)
        # Czyta logi i wyswietla podejrzane IP
        clear
        echo "Czyta aktualne logi i wyswietla podejrzane IP."
        latest_log_file=$(find_latest_log_file)
            if [ -f "$latest_log_file" ]; then
                cut -d" " -f9 "$latest_log_file" | sort | uniq
            else
                echo "Nie znaleziono pliku logów."
            fi

        echo
        exec $0
        
        ;;
    4)
        # Wyjście ze skryptu
        killall Analyzer
        echo "Wyjście."
        exit 0
        ;;
    *)
        echo "Nieprawidłowy wybór. Uruchamianie anulowane."
        exit 1
        ;;
esac
