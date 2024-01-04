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

list_suspicious_ip() {
    echo "Lista podejrzanych IP: "
                latest_log_file=$(find_latest_log_file)
        if [ -f "$latest_log_file" ]; then
            cut -d" " -f9 "$latest_log_file" | sort | uniq
        else
            echo "Nie znaleziono pliku logów."
        fi
    echo
}

block_suspicious_ips() {
    echo "Blokowanie podejrzanych adresów IP"

    # Pobierz aktualny adres IP hosta
    host_ip=$(hostname -I | awk '{print $1}')

    latest_log_file=$(find_latest_log_file)
    if [[ -r "$latest_log_file" ]]; then
        while read -r line; do
            IP=$(echo "$line" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")
            COUNT=$(echo "$line" | grep -oE "Ilość: [0-9]+" | grep -oE "[0-9]+")

            # blokuje liste IP za wyjatkiem IP hosta
            if [[ $COUNT -gt $threshold && $IP != $host_ip ]]; then
                sudo iptables -A INPUT -s $IP -j DROP
                echo "Zablokowano IP: $IP"
            fi
        done < "$latest_log_file"
    else
        echo "Nie znaleziono lub nie można odczytać pliku logów: $latest_log_file"
    fi
}

block_specific_ip() {
    echo "Podaj adres IP do zablokowania:"
    read ip_address
    sudo iptables -A INPUT -s $ip_address -j DROP
    echo "Zablokowano adres IP: $ip_address"
}

unblock_all_ips() {
    echo "Odblokowywanie wszystkich zablokowanych adresów IP."
    sudo iptables -L INPUT -n --line-numbers | grep DROP | awk '{print $1}' | sort -r | while read line; do
        sudo iptables -D INPUT $line
    done
    echo "Wszystkie adresy IP zostały odblokowane."
}

unblock_specific_ip() {
    echo "Podaj adres IP do odblokowania:"
    read ip_address
    sudo iptables -D INPUT -s $ip_address -j DROP
    echo "Odblokowano adres IP: $ip_address"
}

loading() {
        echo -n "Ładowanie"
        for i in $(seq 1 5); do
            sleep 0.2
            echo -n "."
        done
        echo
}

press_to_continue() {
    echo "Naciśnij dowolny klawisz, aby kontynuować..."
    read -n 1 -s -r
    echo
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

if [ ! -d "reports" ]; then
    mkdir reports 
fi

# Petla do while, celem poprawy dzialania skryptu.
while true; do
    clear
# Menu wyboru
    echo "   _                                 _          _  _         _   "
    echo "  /_\    _ _    ___   _ __    __ _  | |  _  _  | \| |  ___  | |_ "
    echo " / _ \  | ' \  / _ \ | '  \  / _' | | | | || | | .' | / -_) |  _|"
    echo "/_/ \_\ |_||_| \___/ |_|_|_| \__'_| |_|  \_' | |_|\_| \___|  \__|"
    echo "                                         |__/                    "

    echo "            ___          _                _               "
    echo "           |   \   ___  | |_   ___   __  | |_   ___   _ _ "
    echo "           | || | / -_| |  _| / -_| / _| |  _| / _ \ | '_|"
    echo "           |___/  \___|  \__| \___| \__|  \__| \___/ |_|  "
                                                
    echo
    echo
    echo "Menu Zarządzania Monitorem Sieci"
    echo
    echo "=========================================================================================="
    echo "1) Uruchom w tle - Przechwytuje pakiety sieciowe, logując je w tle."
    echo "2) Uruchom w terminalu - Wyświetla aktywność sieciową bezpośrednio w terminalu."
    echo "3) Wyświetl podejrzane adresy IP - Pokazuje adresy IP z nietypowym ruchem."
    echo "4) Zablokuj podejrzane adresy IP - Automatycznie blokuje adresy z nietypowym ruchem."
    echo "5) Odblokuj podejrzane adresy IP - Usuwa blokady na adresy IP."
    echo "6) Wyświetl listę blokad IP - Pokazuje obecne zasady blokowania IP w iptables."
    echo "7) Wyświetl raport z logów - Pokazuje szczegółowy raport z ostatniej aktywności."
    echo "8) Zablokuj wybrany adres IP - Umożliwia ręczne blokowanie określonego adresu IP."
    echo "9) Odblokuj wybrany adres IP - Umożliwia ręczne odblokowanie określonego adresu IP."
    echo "=========================================================================================="
    echo "0) Zakoncz działanie programu - Zamyka monitor sieciowy i kończy skrypt."
    echo "------------------------------------------------------------------------------------------"
    echo "r) Read me - jesli chcesz zapoznac sie z opisem programu, wybierz 'r'."
    read -p "Wybierz opcję: " choice


case $choice in
    1)  # Uruchomienie programu w tle
        ./$output >> "$log_file" 2>&1 &
        clear
        echo "Program uruchomiony w tle, PID: $!"
        echo $! > program.pid   #plik z PID programu
        echo
        press_to_continue
        ;;

    2)  # Uruchomienie programu w terminalu
        ./$output | tee -a "$log_file" &
        PID=$!
        echo
        echo "Naciśnij dowolny klawisz, aby zakończyć logowanie danych w terminalu"
        echo
        loading
        read -n 1  # Oczekuj na naciśnięcie klawisza
        kill $PID
        ;;

    3)  # Czyta logi i wyswietla podejrzane IP
        list_suspicious_ip
        press_to_continue
        ;;

    4)  # Blokowanie podejrzanych IP
        block_suspicious_ips
        echo
        press_to_continue
        ;;

    5)  # Odblokowanie podejrzanych IP
        unblock_all_ips
        echo
        press_to_continue
        ;;

    6)  # Wyswietla liste potencjalnie zablokowanych adresow
        sudo iptables -L INPUT -n --line-numbers
        echo
        press_to_continue
        ;;

    7)  # Generuj raport z aktualnie posiadanych logow
        echo "Generowanie raportu, proszę czekać..."
        loading
        if [ ! -f "$log_file" ]; then
            echo
            echo "Plik z logami nie istnieje."
            echo "Wybierz opcje 1 lub 2, aby rozpoczac nowy monitoring sieci."
            exec $0
        else
            ./$output report  # Wywołanie programu z argumentem 'report'
            # Po wygenerowaniu raportu
            clear

            # Pierwsze pytanie
            echo "Raport został wygenerowany."
            echo "Czy chcesz wyswietlic raport?? t/n (tak/nie)"
            read odp1
                if [ "$odp1" = "t" ]; then
                less reports/report.txt 
                else
                    echo "Niepoprawna odpowiedź."
                fi
            clear

            # Drugie pytanie
            echo "Czy chcesz usunąć plik z logami? t/n (tak/nie)"
            read odp2

                if [ "$odp2" = "t" ]; then
                    if [ -f "$log_file" ]; then
                        echo "Usuwanie pliku z logami."
                        rm -f "$log_file"
                        echo "Plik z logami został usunięty."
                        echo "Wybierz opcje 1 lub 2, aby rozpoczac nowy monitoring sieci."
                    else
                        echo "Brak pliku z logami do usunięcia."
                    fi
                elif [ "$odp2" = "n" ]; then
                    echo "Plik z logami nie zostanie usunięty."
                else
                    echo "Niepoprawna odpowiedź. Plik z logami nie zostanie usunięty."
                fi
        fi
        press_to_continue
        ;;

    8) # Blokowanie wybranego adresu IP  
        echo
        list_suspicious_ip
        echo      
        block_specific_ip
        echo
        press_to_continue
        ;;

    9)  # Odblokowanie danego adresu IP
        echo
        echo "Zablokowane adresy IP:"
        sudo iptables -L INPUT -n --line-numbers
        echo
        unblock_specific_ip
        echo
        press_to_continue
        ;;

    0)
        # Wyjście ze skryptu
        killall Analyzer
        echo "Wyjście."
        break
        ;;
    
    r)  # Wyswietla readME
        echo 
        echo "                    AnomalyNet Detector                    "
        echo 
        echo "Przeznaczenie:"
        echo " Proste narzędzie do monitorowania ruchu sieciowego w czasie rzeczywistym."
        echo " Szczegolnie polecany na male serwery np. ct8.pl, oparte o systemy Linux."
        echo " Pozwala na identyfikację różnych rodzajów ruchu sieciowego, w tym potencjalnych anomalii."
        echo ""
        echo "Funkcjonalności:"
        echo " - Analiza pakietów: Rozpoznaje i loguje szczegółowe informacje o każdym przechwyconym pakiecie."
        echo " - Wykrywanie anomalii: Identyfikuje nietypowe wzorce ruchu, takie jak nadmierna liczba pakietów z jednego adresu IP."
        echo " - Obsługa różnych protokołów: Analizuje protokoły TCP, UDP oraz inne."
        echo ""
        echo "Struktura Programu:"
        echo " - main.cpp: Główny plik programu, inicjuje przechwytywanie pakietów i zarządza logowaniem."
        echo " - utils.cpp: Zawiera funkcje pomocnicze."
        echo " - protocol_analysis.cpp: Zawiera funkcje do analizy poszczególnych pakietów i protokołów."
        echo ""
        echo "Jak Uruchomić:"
        echo " - Wymagania: g++ i libpcap."
        echo " - Kompilacja: Skompiluj program z użyciem g++."
        echo " - Uruchomienie: Wybierz opcję uruchomienia programu w skrypcie."
        echo ""
        echo "Opcje Menu:"
        echo " 1. Uruchom w tle - Przechwytuje pakiety sieciowe, logując je w tle."
        echo " 2. Uruchom w terminalu - Wyświetla aktywność sieciową bezpośrednio w terminalu."
        echo " 3. Wyświetl podejrzane adresy IP - Pokazuje adresy IP z nietypowym ruchem."
        echo " 4. Zablokuj podejrzane adresy IP - Automatycznie blokuje adresy z nietypowym ruchem."
        echo " 5. Odblokuj podejrzane adresy IP - Usuwa blokady na adresy IP."
        echo " 6. Wyświetl listę blokad IP - Pokazuje obecne zasady blokowania IP w iptables."
        echo " 7. Wyświetl raport z logów - Pokazuje szczegółowy raport z ostatniej aktywności."
        echo " 8. Zablokuj wybrany adres IP - Umożliwia ręczne blokowanie określonego adresu IP."
        echo " 9. Odblokuj wybrany adres IP - Umożliwia ręczne odblokowanie określonego adresu IP."
        echo " 0. Zakancza działanie programu - Zamyka monitor sieciowy i kończy skrypt."
        echo ""
        echo "Opis Kluczowych Funkcji:"
        echo " - analyzeIPHeader: Analizuje nagłówki IP."
        echo " - detectAnomaly: Wykrywa anomalie w ruchu sieciowym."
        echo " - analyzeTCP/analyzeUDP: Analizuje nagłówki TCP i UDP."
        echo " - analyzeProtocol: Wybiera odpowiednią funkcję analizy na podstawie typu protokołu."
        echo ""
        echo "Dodatkowe informacje:"
        echo " - Logowanie i Rotacja Logów: Zapisuje dane do plików logów. Gdy rozmiar pliku osiągnie 256 kB, tworzony jest nowy plik."
        echo " - Wykrywanie Anomalii: Śledzi liczbę pakietów pochodzących z każdego adresu IP."
        echo " - Tworzy raport na podstawie logow."
        echo "============================================================"
        echo
        press_to_continue
        ;;
    *)
        # Restart skryptu w przypadku wybrania zlej wartosci
        echo "Nieprawidłowy wybór. Wybierz jeszcze raz, badz wybierz '0' aby wyjsc!."
        press_to_continue
        ;;
    esac
done