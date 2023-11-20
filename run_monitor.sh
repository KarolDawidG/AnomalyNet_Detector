#!/bin/bash

# Nazwa pliku wyjściowego
output="Analizer"

# Kompilacja programu
g++ main.cpp -o $output -lpcap

# Sprawdzenie, czy kompilacja się powiodła
if [ $? -ne 0 ]; then
    echo "Kompilacja nie powiodła się."
    exit 1
fi

# Nadanie uprawnień do przechwytywania pakietów (opcjonalne, wymaga sudo)
sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' $output

# Uruchomienie programu w tle i zapis logów
./$output | tee log.txt
echo "Program uruchomiony w tle, PID: $!"

# Zapis PID do pliku
echo $! > program.pid

