```
     ___      .__   __.   ______   .___  ___.      ___       __      ____    ____ 
    /   \     |  \ |  |  /  __  \  |   \/   |     /   \     |  |     \   \  /   / 
   /  ^  \    |   \|  | |  |  |  | |  \  /  |    /  ^  \    |  |      \   \/   /  
  /  /_\  \   |  . `  | |  |  |  | |  |\/|  |   /  /_\  \   |  |       \_    _/   
 /  _____  \  |  |\   | |  `--'  | |  |  |  |  /  _____  \  |  `----.    |  |     
/__/     \__\ |__| \__|  \______/  |__|  |__| /__/     \__\ |_______|    |__|     
.__   __.  _______ .___________.
|  \ |  | |   ____||           |
|   \|  | |  |__   `---|  |----`
|  . `  | |   __|      |  |     
|  |\   | |  |____     |  |     
|__| \__| |_______|    |__|                                                                                                                   
 _______   _______ .___________. _______   ______ .___________.  ______   .______      
|       \ |   ____||           ||   ____| /      ||           | /  __  \  |   _  \     
|  .--.  ||  |__   `---|  |----`|  |__   |  ,----'`---|  |----`|  |  |  | |  |_)  |    
|  |  |  ||   __|      |  |     |   __|  |  |         |  |     |  |  |  | |      /     
|  '--'  ||  |____     |  |     |  |____ |  `----.    |  |     |  `--'  | |  |\  \----.
|_______/ |_______|    |__|     |_______| \______|    |__|      \______/  | _| `._____|
                                                                                       
```

# Project Description "AnomalyNet Detector"
## Goals and Assumptions
The "AnomalyNet Detector" project aims to create an advanced tool for real-time network traffic monitoring. The key assumption of the project is to provide users with an easy-to-use and efficient tool for network packet analysis and identification of potential network anomalies, such as unusual traffic patterns or excessive activity from individual IP addresses.

## Possible Applications
"AnomalyNet Detector" can be used in various scenarios, including:
- Network security monitoring in small and medium-sized enterprises.
- Detection and prevention of DDoS attacks and other network threats.
- Analysis and management of network traffic on servers, including Linux-based servers.
- Education in network security and traffic analysis.

## Technologies and Software
### The project utilizes the following technologies and software:
1. C++ programming language to create the main program analyzing network traffic.
2. Bash script for managing the program and user interaction.
3. G++ and the libpcap library for compiling and capturing network packets.

## Requirements for Running
### To run "AnomalyNet Detector," the following are required:
1. Linux operating system.
2. Installed g++ and libpcap tools.
3. Administrator privileges (sudo) to manage iptables rules and capture network packets.

## Installation, Launch, and Usage
### Installation:
1. Clone the project repository or download the source files.
2. Install the required tools (g++, libpcap).

## Launch:
1. Open the terminal and go to the project directory.
2. Run the bash script (./run_monitor.sh), which will compile and run the program.

## Usage:
After running the script, the user has access to an interactive menu from which they can select one of the available options, such as starting monitoring, displaying reports, blocking or unblocking IP addresses, etc.
Network monitoring takes place in the background, recording activity logs and detecting potential anomalies.
The user can check logs, generate reports, or manage network rules at any time using a simple console interface.

## Features
- Packet Analysis: The program recognizes and logs detailed information about each captured packet, including source and destination addresses, as well as detailed information about the protocol.
- Anomaly Detection: The program identifies unusual traffic patterns, such as an excessive number of packets originating from a single IP address.
- Support for Various Protocols: The program can analyze TCP, UDP, and other protocols, providing detailed information about traffic characteristics.
- Reporting: Generating reports from logs created during network monitoring.
- IP Blocking: The ability to block all or individual suspicious IP addresses, listing blocked addresses, and easy unblocking - all from within the application.

## Program Structure
### The program consists of the following modules:
# C++
- main.cpp: The main program file, initiates packet capture and manages logging.
- utils.cpp: Contains auxiliary functions, including functions for logging time and managing log files.
- protocol_analysis.cpp: Contains functions for analyzing individual packets and protocols.

# Bash
- run_monitor.sh: A simple script responsible for controlling the application from the terminal.

## Menu Options
1. Run in the background: The program is run in the background, logging network activity.
2. Run in the terminal: The program is run in the terminal, displaying network activity in real-time.
3. Display suspicious IP addresses: The script analyzes logs and displays IPs with unusual traffic.
4. Block suspicious IP addresses: The script automatically blocks IPs generating excessive network activity.
5. Unblock all blocked IP addresses: Removes all IP blocking rules from iptables.
6. Display IP block list: Displays the current iptables configuration.
7. Display report from logs: Generates and optionally displays a detailed network activity report.
8. Block a specific IP address: Allows manually adding a blocking rule for a specific IP address.
9. Unblock a specific IP address: Allows manually removing a blocking rule for a specific IP address.
0. End program operation: Closes the program and ends the script.
- r. Read me - if you want to familiarize yourself with the program description, select 'r'.

## Description of Key Functions
- analyzeIPHeader: Analyzes the IP header and logs IP addresses.
- detectAnomaly: Detects anomalies in network traffic and logs them.
- analyzeTCP/analyzeUDP: Analyzes TCP and UDP headers, respectively.
- analyzeProtocol: Chooses the appropriate analysis function based on the packet's protocol type.

## Additionally:
- Logging and Log Rotation: The program saves data to log files with names containing the date. When the log file size reaches 256 kB, a new log file is created.
- Anomaly Detection: The program tracks the number of packets coming from each IP address. When this number exceeds 1000, the program logs this as a potential anomaly.
- Reporting: Generating simple reports based on logs.

# Running the Bash Script "AnomalyNet Detector"
## Checking System Requirements
The script checks if g++ (C++ compiler) and libpcap (packet capturing library) are installed in the system.

## Compiling the Program
Using g++, the script compiles the source files of the program (main.cpp, utils.cpp, protocol_analysis.cpp) into an executable file "Analyzer".

## Granting Permissions
The script sets appropriate permissions on the compiled program so it can capture network packets.

## Creating Folders for Logs and Reports
The script creates "logs" and "reports" folders, if they do not exist, for storing logs and reports generated by the program.

## Interactive Menu
The user is presented with an interactive menu with various options for managing the program.

## Additional Functions
Auxiliary functions such as loading and press_to_continue improve the interactivity and usability of the script.

## Managing the Script
After each action, the user will be returned to the main menu. The script is smooth and user-friendly, as there is no need to restart it after each action.

# Screenshots
### Main Menu
<img src="/img/menu.png" width="auto%" height="auto">

### Option 1 and 2
<p align="center">
     <img src="/img/1 praca w tle.png" width="45%" height="auto">
     <img src="/img/praca w terminalu.png" width="45%" height="auto">
</p>

### Option 3 and 4
<p align="center">
     <img src="/img/lista podejrzanych.png" width="45%" height="auto">
     <img src="/img/blokowanie wszystkich ip.png" width="45%" height="auto">
</p>

### Option 5 and 6
<p align="center">
     <img src="/img/odblokowanie wszystkiego.png" width="45%" height="auto">
     <img src="/img/lista zablokowanych ip.png" width="45%" height="auto">
</p>

### Option 7
<img src="/img/raport 2.png" width="auto" height="auto">

### Option 8 and 9
<p align="center">
     <img src="/img/blokada wybranego ip.png" width="45%" height="auto">
     <img src="/img/odblokowanie 2.png" width="45%" height="auto">
</p>

### Option r - to display readMe
<img src="/img/readme 1.png" width="auto" height="auto">

<h1 align="center"> ] > ============================== < [ </h1>

```
.______     ______    __           _______. __  ___      ___      
|   _  \   /  __  \  |  |         /       ||  |/  /     /   \     
|  |_|  | |  |  |  | |  |        |   (----`|  '  /     /  ^  \    
|   ___/  |  |  |  | |  |         \   \    |    <     /  /_\  \   
|  |      |  `--'  | |  `----..----)   |   |  .  \   /  _____  \  
| _|       \______/  |_______||_______/    |__|\__\ /__/     \__\ 

____    __    ____  _______ .______           _______.       __       ___      
\   \  /  \  /   / |   ____||   _  \         /       |      |  |     /   \     
 \   \/    \/   /  |  |__   |  |_|  |       |   (----`      |  |    /  ^  \    
  \            /   |   __|  |      /         \   \    .--.  |  |   /  /_\  \   
   \    /\    /    |  |____ |  |\  \----..----)   |   |  `--'  |  /  _____  \  
    \__/  \__/     |_______|| _| `._____||_______/     \______/  /__/     \__\ 
                                                                               
                                                                  
```                               

# Opis Projektu "AnomalyNet Detector"
## Cele i Założenia
Projekt "AnomalyNet Detector" ma na celu stworzenie zaawansowanego narzędzia do monitorowania ruchu sieciowego w czasie rzeczywistym. Kluczowym założeniem projektu jest dostarczenie użytkownikom łatwego w obsłudze i wydajnego narzędzia do analizy pakietów sieciowych oraz identyfikacji potencjalnych anomalii sieciowych, takich jak nietypowe wzorce ruchu czy nadmierna aktywność z poszczególnych adresów IP.

## Możliwe Zastosowania
### "AnomalyNet Detector" może być wykorzystany w różnych scenariuszach, w tym:
- Monitorowanie bezpieczeństwa sieci w małych i średnich przedsiębiorstwach.
- Wykrywanie i prewencja ataków DDoS i innych zagrożeń sieciowych.
- Analiza i zarządzanie ruchem sieciowym na serwerach, w tym na serwerach opartych o systemy Linux.
- Edukacja w zakresie bezpieczeństwa sieci i analizy ruchu sieciowego.

## Technologie i Oprogramowanie
### Projekt wykorzystuje następujące technologie i oprogramowanie:
1. Język programowania C++ do tworzenia głównego programu analizującego ruch sieciowy.
2. Skrypt bash do zarządzania programem i interakcji z użytkownikiem.
3. G++ oraz biblioteka libpcap do kompilacji i przechwytywania pakietów sieciowych.

## Wymagania do Uruchomienia
### Aby uruchomić "AnomalyNet Detector", wymagane jest:
1. System operacyjny Linux.
2. Zainstalowane narzędzia g++ i libpcap.
3. Uprawnienia administratora (sudo) do zarządzania zasadami iptables oraz przechwytywania pakietów sieciowych.

## Instalacja, Uruchomienie i Użytkowanie
### Instalacja:
1. Sklonuj repozytorium projektu lub pobierz pliki źródłowe.
2. Zainstaluj wymagane narzędzia (g++, libpcap).

## Uruchomienie:
- Otwórz terminal i przejdź do katalogu z projektem.
- Uruchom skrypt bash (./run_monitor.sh), który skompiluje i uruchomi program.

## Użytkowanie:
Po uruchomieniu skryptu, użytkownik ma dostęp do interaktywnego menu, z którego może wybrać jedną z dostępnych opcji, takich jak uruchomienie monitorowania, wyświetlenie raportów, blokowanie lub odblokowywanie adresów IP itp.
Monitorowanie sieci odbywa się w tle, zapisując logi aktywności i wykrywając potencjalne anomalie.
Użytkownik może w dowolnym momencie sprawdzić logi, wygenerować raporty lub zarządzać zasadami sieciowymi za pomocą prostego interfejsu konsolowego.

## Funkcjonalności
- Analiza pakietów: Program rozpoznaje i loguje szczegółowe informacje o każdym przechwyconym pakiecie, w tym adresy źródłowe i docelowe, a także szczegółowe informacje o protokole.
- Wykrywanie anomalii: Program identyfikuje nietypowe wzorce ruchu, takie jak nadmierna liczba pakietów pochodzących z jednego adresu IP.
- Obsługa różnych protokołów: Program potrafi analizować protokoły TCP, UDP oraz inne, dostarczając szczegółowych informacji o charakterystyce ruchu.
- Raportowanie: Generowanie raportow z logow, ktore powstaja podczas monitoringu sieci.
- Blokowanie IP: Mozliwosc blokowania wszystkich, badz pojedynczych podejrzanych adresow IP, listowanie zablokowanych, a takze latwe odblokowywanie - wszystko z poziomu aplikacji. 
  
## Struktura Programu
### Program składa się z następujących modułów:
# C++
- main.cpp: Główny plik programu, inicjuje przechwytywanie pakietów i zarządza logowaniem.
- utils.cpp: Zawiera funkcje pomocnicze, w tym funkcje do logowania czasu i zarządzania plikami logów.
- protocol_analysis.cpp: Zawiera funkcje do analizy poszczególnych pakietów i protokołów.

# Bash
- run_monitor.sh: prosty skrypt odpowiedzialny za sterowanie aplikacja z poziomu terminala.

## Opcje Menu
1. Uruchom w tle: Program jest uruchamiany w tle, logując aktywność sieciową.
2. Uruchom w terminalu: Program jest uruchamiany w terminalu, wyświetlając aktywność sieciową na bieżąco.
3. Wyświetl podejrzane adresy IP: Skrypt analizuje logi i wyświetla adresy IP z nietypowym ruchem.
4. Zablokuj podejrzane adresy IP: Skrypt automatycznie blokuje adresy IP generujące nadmierną aktywność sieciową.
5. Odblokuj wszystkie zablokowane adresy IP: Usuwa wszystkie reguły blokowania IP z iptables.
6. Wyświetl listę blokad IP: Wyświetla aktualną konfigurację iptables.
7. Wyświetl raport z logów: Generuje i opcjonalnie wyświetla szczegółowy raport aktywności sieciowej.
8. Zablokuj wybrany adres IP: Pozwala na ręczne dodanie reguły blokowania dla określonego adresu IP.
9. Odblokuj wybrany adres IP: Pozwala na ręczne usunięcie reguły blokowania dla określonego adresu IP.
0. Zakończ działanie programu: Zamyka program i kończy działanie skryptu.
- r. Read me - jesli chcesz zapoznac sie z opisem programu, wybierz 'r'.

## Opis Kluczowych Funkcji
- analyzeIPHeader: Analizuje nagłówek IP i loguje adresy IP.
- detectAnomaly: Wykrywa anomalie w ruchu sieciowym i loguje je.
- analyzeTCP/analyzeUDP: Analizuje odpowiednio nagłówki TCP i UDP.
- analyzeProtocol: Wybiera odpowiednią funkcję analizy na podstawie typu protokołu w pakiecie.

## Ponadto:
- Logowanie i Rotacja Logów: Program zapisuje dane do plików logów z nazwami zawierającymi datę. Gdy rozmiar pliku logu osiągnie 256 kB, tworzony jest nowy plik logu.
- Wykrywanie Anomalii: Program śledzi liczbę pakietów pochodzących z każdego adresu IP. Gdy liczba ta przekroczy 1000, program loguje to jako potencjalną anomalię.
- Raportowanie: Generowanie prostych raportow na podstawie logow.

# Przebieg Skryptu Bash "AnomalyNet Detector"
## Sprawdzenie Wymagań Systemowych
Skrypt sprawdza, czy g++ (kompilator C++) oraz libpcap (biblioteka do przechwytywania pakietów sieciowych) są zainstalowane w systemie.

## Kompilacja Programu
Wykorzystując g++, skrypt kompiluje pliki źródłowe programu (main.cpp, utils.cpp, protocol_analysis.cpp) do wykonywalnego pliku "Analyzer".

## Nadanie Uprawnień
Skrypt ustawia odpowiednie uprawnienia na skompilowany program, aby mógł on przechwytywać pakiety sieciowe.

## Tworzenie Folderów Dla Logów i Raportów
Skrypt tworzy foldery "logs" i "reports", jeśli te nie istnieją, do przechowywania logów i raportów generowanych przez program.

## Interaktywne Menu
Użytkownikowi prezentowane jest interaktywne menu z różnymi opcjami do zarządzania programem.

## Dodatkowe Funkcje
Funkcje pomocnicze takie jak loading oraz press_to_continue poprawiają interaktywność i użyteczność skryptu.

## Zarządzanie Skryptem
Po każdej wykonanej akcji, użytkownik zostanie przeniesiony z powrotem do menu głównego. Skrypt jest płynny i przyjazny dla użytkownika, ponieważ nie ma potrzeby restartowania go po każdej akcji.
