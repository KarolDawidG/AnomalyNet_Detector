# Opis Projektu "AnomalyNet Detector"
## Cele i Założenia
Projekt "AnomalyNet Detector" ma na celu stworzenie zaawansowanego narzędzia do monitorowania ruchu sieciowego w czasie rzeczywistym. Kluczowym założeniem projektu jest dostarczenie użytkownikom łatwego w obsłudze i wydajnego narzędzia do analizy pakietów sieciowych oraz identyfikacji potencjalnych anomalii sieciowych, takich jak nietypowe wzorce ruchu czy nadmierna aktywność z poszczególnych adresów IP.

### Możliwe Zastosowania
"AnomalyNet Detector" może być wykorzystany w różnych scenariuszach, w tym:
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

## Przebieg Skryptu Bash "AnomalyNet Detector"
### Sprawdzenie Wymagań Systemowych
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

# Screeny
## Niebawem
### Prace
w toku...
