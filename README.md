# Opis Programu "Analyzer"
### Przeznaczenie
Program "Analyzer" to zaawansowane narzędzie do monitorowania ruchu sieciowego w czasie rzeczywistym. Jest przeznaczone do analizowania pakietów sieciowych przechwytywanych na określonym interfejsie sieciowym, umożliwiając identyfikację różnych rodzajów ruchu sieciowego, w tym potencjalnych anomalii.

### Funkcjonalności
Analiza pakietów: Program rozpoznaje i loguje szczegółowe informacje o każdym przechwyconym pakiecie, w tym adresy źródłowe i docelowe, a także szczegółowe informacje o protokole.
Wykrywanie anomalii: Program identyfikuje nietypowe wzorce ruchu, takie jak nadmierna liczba pakietów pochodzących z jednego adresu IP.
Obsługa różnych protokołów: Program potrafi analizować protokoły TCP, UDP oraz inne, dostarczając szczegółowych informacji o charakterystyce ruchu.
Struktura Programu
Program składa się z następujących modułów:

main.cpp: Główny plik programu, inicjuje przechwytywanie pakietów i zarządza logowaniem.
utils.cpp: Zawiera funkcje pomocnicze, w tym funkcje do logowania czasu i zarządzania plikami logów.
protocol_analysis.cpp: Zawiera funkcje do analizy poszczególnych pakietów i protokołów.
Jak uruchomić
Wymagania: Upewnij się, że masz zainstalowane g++ i bibliotekę libpcap.
Kompilacja: Uruchom skrypt, który skompiluje program z użyciem g++.
Uruchomienie: Wybierz opcję uruchomienia programu w skrypcie.
Opcje Menu
Uruchom w tle i zapisz logi do pliku: Uruchamia program w tle, logując wszystkie dane do pliku.
Uruchom w terminalu: Uruchamia program w terminalu, wyświetlając logi na bieżąco.
Wyświetl podejrzane adresy IP: Analizuje zapisane logi i wyświetla listę podejrzanych adresów IP.
Zakończ działanie programu: Zamyka program i skrypt.
Opis Kluczowych Funkcji
analyzeIPHeader: Analizuje nagłówek IP i loguje adresy IP.
detectAnomaly: Wykrywa anomalie w ruchu sieciowym i loguje je.
analyzeTCP/analyzeUDP: Analizuje odpowiednio nagłówki TCP i UDP.
analyzeProtocol: Wybiera odpowiednią funkcję analizy na podstawie typu protokołu w pakiecie.
Logowanie i Rotacja Logów
Program zapisuje dane do plików logów z nazwami zawierającymi datę. Gdy rozmiar pliku logu osiągnie 1 MB, tworzony jest nowy plik logu.

Wykrywanie Anomalii
Program śledzi liczbę pakietów pochodzących z każdego adresu IP. Gdy liczba ta przekroczy 1000, program loguje to jako potencjalną anomalię.