#!/bin/bash
output="Analyzer"
source_files="main.cpp utils/utils.cpp protocol_analysis.cpp"
log_directory="logs"
log_file_prefix="anomalyDetector"
log_file="logs/mainLogFile.txt"
threshold=1000

find_latest_log_file() {
    ls -Art $log_directory/$log_file_prefix-*.txt 2>/dev/null | tail -n 1
}

block_suspicious_ips() {
    echo "Blokowanie podejrzanych adresów IP..."

    latest_log_file=$(find_latest_log_file)
    if [[ -r "$latest_log_file" ]]; then
        while read -r line; do
            IP=$(echo "$line" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")
            COUNT=$(echo "$line" | grep -oE "Ilość: [0-9]+" | grep -oE "[0-9]+")

            if [[ $COUNT -gt $threshold ]]; then
                sudo iptables -A INPUT -s $IP -j DROP
                echo "Zablokowano IP: $IP"
            fi
        done < "$latest_log_file"
    else
        echo "Nie znaleziono lub nie można odczytać pliku logów: $latest_log_file"
    fi
}


unblock_all_ips() {
    echo "Odblokowywanie wszystkich zablokowanych adresów IP..."
    sudo iptables -L INPUT -n --line-numbers | grep DROP | awk '{print $1}' | sort -r | while read line; do
        sudo iptables -D INPUT $line
    done
    echo "Wszystkie adresy IP zostały odblokowane."
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

# Tworzenie odpowiednich folderow
if [ ! -d "logs" ]; then
    mkdir logs
fi

# Menu wyboru
echo "Wybierz opcję uruchomienia programu:"
echo "1) Uruchom w tle."
echo "2) Uruchom w terminalu."
echo "3) Wyswietl podejrzane adresy IP."
echo "4) Zablokuj podejrzane adresy IP"
echo "5) Odblokuj podejrzane adresy IP"
echo "6) Wyswietl iptable z lista blokowanych IP"
echo "9) Zakoncz dzialanie programu."
read -p "Wybór: " choice

case $choice in
    1)
        # Uruchomienie programu w tle
        ./$output > $log_file 2>&1 &
        clear
        echo "Program uruchomiony w tle, PID: $!"
        echo $! > program.pid   #plik z PID programu
        echo
        exec $0 # Uruchomienie skryptu ponownie
        ;;
    2)
        # Uruchomienie programu w terminalu
        ./$output | tee $log_file
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
        clear
        # Uruchamia funkcję do blokowania podejrzanych IP
        block_suspicious_ips
        echo
        exec $0 
        ;;
    5)
        clear
        # Uruchamia funkcję do odblokowania podejrzanych IP
        unblock_all_ips
        echo
        exec $0 
        ;;
    6)
        clear
        sudo iptables -L INPUT -n --line-numbers
        echo
        exec $0
        ;;
    9)
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