#!/bin/sh
set -e
CXX="g++"
LDFLAGS_LIB="-shared"
LDFLAGS_MAIN="-ldl"
EXEC_NAME="cipher_tool"

BOOST_INCLUDE_DIR=""
if [ -d "/opt/homebrew/include" ]; then
    BOOST_INCLUDE_DIR="/opt/homebrew/include"
elif [ -d "/usr/local/include" ]; then
    if [ -f "/usr/local/include/boost/version.hpp" ]; then
        BOOST_INCLUDE_DIR="/usr/local/include"
    fi
fi

CUSTOM_CXXFLAGS=""
if [ -n "$BOOST_INCLUDE_DIR" ]; then
    CUSTOM_CXXFLAGS="-I${BOOST_INCLUDE_DIR}"
fi

CXXFLAGS="-std=c++17 -Wall -fPIC -O2 ${CUSTOM_CXXFLAGS}"

echo "Сборка libpolybius.so"
$CXX $CXXFLAGS -DPOLYBIUS_EXPORTS -c polybius.cpp -o polybius.o
$CXX $CXXFLAGS -DPOLYBIUS_EXPORTS -c polybius_export.cpp -o polybius_export.o
$CXX $LDFLAGS_LIB polybius.o polybius_export.o -o libpolybius.so

echo "Сборка libatbash.so"
$CXX $CXXFLAGS -DATBASH_EXPORTS -c atbash.cpp -o atbash.o
$CXX $CXXFLAGS -DATBASH_EXPORTS -c atbash_export.cpp -o atbash_export.o
$CXX $LDFLAGS_LIB atbash.o atbash_export.o -o libatbash.so

echo "Сборка librsa.so"
$CXX $CXXFLAGS -c rsa.cpp -o rsa.o
$CXX $CXXFLAGS -c rsa_export.cpp -o rsa_export.o
$CXX $LDFLAGS_LIB rsa.o rsa_export.o -o librsa.so

echo "Сборка основного приложения ${EXEC_NAME}"
$CXX $CXXFLAGS main.cpp -o $EXEC_NAME $LDFLAGS_MAIN

echo "Очистка временных файлов"
rm -f *.o

echo "Сборка завершена!"
echo "Запустите программу: ./${EXEC_NAME}"
