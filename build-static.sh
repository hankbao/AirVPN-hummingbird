#!/bin/sh

#
# Build static binary for hummingbird and distribution tarball
#
# Version 1.0 - ProMIND
#

OS_NAME=`uname`

BASE_NAME=hummingbird

INC_DIR=..
OPENVPN3=${INC_DIR}/openvpn3-airvpn
ASIO=${INC_DIR}/asio

VERSION=`grep -r "#define HUMMINGBIRD_VERSION" src/include/hummingbird.hpp | cut -f 2 -d \" | sed -e 's/ /-/g'`

case $OS_NAME in
    Linux)
        OS_ARCH_NAME=`uname -m`
        BIN_FILE=${BASE_NAME}-linux-${OS_ARCH_NAME}
        SHA_CMD=sha512sum

        echo "Building static ${BASE_NAME} ${VERSION} for Linux ${OS_ARCH_NAME}"

        SOURCES="src/hummingbird.cpp \
                 src/localnetwork.cpp \
                 src/dnsmanager.cpp \
                 src/netfilter.cpp \
                 src/execproc.c \
                 src/loadmod.c
                "

        case $OS_ARCH_NAME in
            x86_64)
                STATIC_LIB_DIR=/usr/lib64
                LIB_DIR=/usr/lib64
                break
                ;;

            armv7l)
                STATIC_LIB_DIR=/usr/lib/arm-linux-gnueabihf
                LIB_DIR=/usr/local/lib
                break
                ;;

            aarch64)
                STATIC_LIB_DIR=/usr/lib/aarch64-linux-gnu
                LIB_DIR=/usr/local/lib
                break
                ;;
        esac

        COMPILE="g++ -fwhole-program -Ofast -Wall -Wno-sign-compare -Wno-unused-parameter -std=c++14 -flto=4 -Wl,--no-as-needed -Wunused-local-typedefs -Wunused-variable -Wno-shift-count-overflow -pthread -DUSE_MBEDTLS -DUSE_ASIO -DASIO_STANDALONE -DASIO_NO_DEPRECATED -I${ASIO}/asio/include -DHAVE_LZ4 -I${OPENVPN3} ${SOURCES} ${LIB_DIR}/libmbedtls.a ${LIB_DIR}/libmbedx509.a ${LIB_DIR}/libmbedcrypto.a ${STATIC_LIB_DIR}/liblz4.a ${STATIC_LIB_DIR}/libz.a ${STATIC_LIB_DIR}/liblzma.a -o ${BIN_FILE}"

        break
	    ;;

    Darwin)
        BIN_FILE=${BASE_NAME}-macos
        SHA_CMD="shasum -a 512"
        LIB_DIR=/usr/local/lib

        echo "Building static ${BASE_NAME} ${VERSION} for macOS"

        SOURCES="src/hummingbird.cpp \
                 src/localnetwork.cpp \
                 src/netfilter.cpp \
                 src/execproc.c
                "

        COMPILE="clang++ -Ofast -Wall -Wno-tautological-compare -Wno-unused-private-field -Wno-c++1y-extensions -framework CoreFoundation -framework SystemConfiguration -framework IOKit -framework ApplicationServices -Wno-sign-compare -Wno-unused-parameter -std=c++14 -Wunused-local-typedefs -Wunused-variable -Wno-shift-count-overflow -pthread -DBOOST_ASIO_DISABLE_KQUEUE -DUSE_MBEDTLS -DUSE_ASIO -DASIO_STANDALONE -DASIO_NO_DEPRECATED -I${ASIO}/asio/include -DHAVE_LZ4 -I${OPENVPN3} $SOURCES -lz -lresolv ${LIB_DIR}/libmbedtls.a ${LIB_DIR}/libmbedx509.a ${LIB_DIR}/libmbedcrypto.a ${LIB_DIR}/liblz4.a -o $BIN_FILE"

	    break
	    ;;

    *)
	    echo "Unsupported system"
        exit 1
	    ;;
esac

OUT_DIR_NAME=${BIN_FILE}-${VERSION}
TAR_FILE_NAME=${OUT_DIR_NAME}.tar.gz
TAR_CHK_FILE_NAME=${TAR_FILE_NAME}.sha512

echo

echo "Compiling sources"

$COMPILE

if [ -d $OUT_DIR_NAME ]
then
    rm -r ${OUT_DIR_NAME}
fi

mkdir ${OUT_DIR_NAME}

strip ${BIN_FILE}

echo

echo "Done compiling ${BIN_FILE}"

echo

echo "Create tar file for distribution"

echo

cp ${BIN_FILE} ${OUT_DIR_NAME}/${BASE_NAME}
cp README.md ${OUT_DIR_NAME}
cp LICENSE.md ${OUT_DIR_NAME}
cp Changelog.txt ${OUT_DIR_NAME}

$SHA_CMD ${OUT_DIR_NAME}/${BASE_NAME} > ${OUT_DIR_NAME}/${BASE_NAME}.sha512

if [ -f ${TAR_FILE_NAME} ]
then
    rm ${TAR_FILE_NAME}
fi

tar czf ${TAR_FILE_NAME} ${OUT_DIR_NAME}

if [ -f ${TAR_CHK_FILE_NAME} ]
then
    rm ${TAR_CHK_FILE_NAME}
fi

$SHA_CMD ${TAR_FILE_NAME} > ${TAR_CHK_FILE_NAME}

rm -r ${OUT_DIR_NAME}

echo "tar file: ${TAR_FILE_NAME}"
echo "tar checksum file: ${TAR_CHK_FILE_NAME}"
echo
echo "Done."
