#!/bin/sh

#
# Build dynamnc binary for hummingbird - mbedtls
#
# Version 1.0 - ProMIND
#

BASE_NAME=hummingbird

INC_DIR=..
OPENVPN3=${INC_DIR}/openvpn3-airvpn
ASIO=${INC_DIR}/asio

SOURCES="src/hummingbird.cpp \
         src/localnetwork.cpp \
         src/dnsmanager.cpp \
         src/netfilter.cpp \
         src/execproc.c \
         src/loadmod.c
        "

BIN_FILE=${BASE_NAME}

COMPILE="g++ -fwhole-program -Ofast -Wall -Wno-sign-compare -Wno-unused-parameter -std=c++14 -flto=4 -Wl,--no-as-needed -Wunused-local-typedefs -Wunused-variable -Wno-shift-count-overflow -pthread -DUSE_MBEDTLS -DUSE_ASIO -DASIO_STANDALONE -DASIO_NO_DEPRECATED -I${ASIO}/asio/include -DHAVE_LZ4 -I${OPENVPN3} ${SOURCES} -lmbedtls -lmbedx509 -lmbedcrypto -llz4 -llzma -o ${BIN_FILE}"

echo $COMPILE

$COMPILE

strip ${BIN_FILE}
