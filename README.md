# Hummingbird for Linux and macOS

#### Free and open source OpenVPN 3 client based on AirVPN's OpenVPN 3 library fork

### Version 1.0 - Release date 27 December 2019


**Main features:**

* Lightweight and stand alone binary
* No heavy framework required, no GUI
* Tiny RAM footprint
* Lightning fast
* Based on [OpenVPN 3 library fork by AirVPN](https://github.com/AirVPN/openvpn3-airvpn) with tons of critical bug fixes from the main branch, new ciphers support and never seen before features
* ChaCha20-Poly1305 cipher support on both Control and Data Channel providing great performance boost on ARM, Raspberry PI and any Linux-based platform not supporting AES-NI. *Note:* ChaCha20 support for Android had been already implemented in [our free and open source Eddie Android edition](https://airvpn.org/forums/topic/44201-eddie-android-edition-24-released-chacha20-support/)
* robust leaks prevention through Network Lock based either on iptables, nftables or pf through automatic detection
* proper handling of DNS push by VPN servers, working with resolv.conf as well as any operational mode of systemd-resolved additional features

## Contents

* [How to install AirVPN Hummingbird client for Linux - Raspberry and macOS](#how-to-install-airvpn-hummingbird-client-for-linux-raspberry-and-macos)
  * [Requirements](#requirements)
  * [Linux x86-64 Installation](#linux-x86-64-installation)
  * [Raspberry - Raspbian - Linux ARM 32 bit Installation](#raspberry-raspbian-linux-arm-32-bit-installation)
  * [Raspberry - Linux ARM 64 bit Installation](#raspberry-linux-arm-64-bit-installation)
  * [macOS Installation](#macos-installation)
* [Running the Hummingbird Client](#running-the-hummingbird-client)
  * [Start a connection](#start-a-connection)
  * [Stop a connection](#stop-a-connection)
  * [Start a connection with a specific cipher](#start-a-connection-with-a-specific-cipher)
  * [Disable the network filter and lock](#disable-the-network-filter-and-lock)
  * [Ignore the DNS servers pushed by the VPN server](#ignore-the-dns-servers-pushed-by-the-vpn-server)
* [Network Filter and Lock](#network-filter-and-lock)
* [DNS Management in Linux](#dns-management-in-linux)
* [DNS Management in macOS](#dns-management-in-macos)
* [Recover Your Network Settings](#recover-your-network-settings)
* [Compile Hummingbird from Sources](#compile-hummingbird-from-sources)
  * [Build Linux Dynamic Binary](#build-linux-dynamic-binary)
  * [Build Linux - ARM and macOS Static Binary](#build-linux-arm-and-macos-static-binary)

  
## How to install AirVPN Hummingbird client for Linux - Raspberry and macOS

Hummingbird is distributed in binary forms and the complete source code is available in the its [gitlab repository](https://gitlab.com/AirVPN/hummingbird). For more information, feedback and latest news, please refer to [AirVPN forum](https://airvpn.org/forums/) and related threads


### Requirements

**Linux**

* x86-64, ARM 32 or ARM 64 bit CPU
* A reasonably recent Linux distribution
* tar
* sha512sum (optional)
* ldd (optional)

**Raspberry**

* Linux Raspbian distribution or Linux ARM 64 bit distribution
* tar
* sha512sum (optional)
* ldd (optional)


**macOS**

* macOS Mojave or higher version
* tar
* shasum (optional)
* otool (optional)


## Linux x86-64 Installation

* Download [hummingbird-linux-1.0.tar.gz](https://gitlab.com/AirVPN/hummingbird/blob/master/binary/hummingbird-linux-x86_64-1.0.tar.gz)
* (optional) Download [hummingbird-linux-1.0.tar.gz.sha512](https://gitlab.com/AirVPN/hummingbird/blob/master/binary/hummingbird-linux-x86_64-1.0.tar.gz.sha512) This file is required to check the integrity of the above tar archive. It is not mandatory but it is strongly advised to download this file and check the tar archive integrity
* [optional] Open a terminal window
* [optional] Check the integrity of the tar archive by issuing this command: `sha512sum --check hummingbird-linux-1.0.tar.gz.sha512`
* [optional] Make sure the command responds with `hummingbird-linux-1.0.tar.gz: OK`
* Change your current directory to a convenient place, such as your home directory. This can be done by issuing the command `cd ~`
* Extract the tar archive by issuing this command on your terminal window: `tar xvf hummingbird-linux-1.0.tar.gz`
* A new directory will be created: `hummingbird-linux-1.0`
* Move into this new directory with command `cd hummingbird-linux-1.0`
* [optional] Check the integrity of binary file `hummingbird`. Issue this command from your terminal window: `sha512sum --check hummingbird.sha512`
* [optional] Make sure the command responds with `hummingbird: OK`
* [optional] Check dynamic library availability. Issue the command `ldd hummingbird` and make sure all the required dynamic libraries are available. No line of the output must contain "not found"
* The Linux client is now ready to be used and possibly copied to a different directory of your system, such as `/usr/bin` or `/usr/local/bin`

**Please note hummingbird client needs root privileges. Your user must therefore be included in your system's "sudoers" (depending on specific Linux distribution)**

 
## Raspberry - Raspbian - Linux ARM 32 bit Installation

* Download [hummingbird-armv7l-1.0.tar.gz](https://gitlab.com/AirVPN/hummingbird/blob/master/binary/hummingbird-linux-armv7l-1.0.tar.gz)
* [optional] Download [hummingbird-armv7l-1.0.tar.gz.sha512](https://gitlab.com/AirVPN/hummingbird/blob/master/binary/hummingbird-linux-armv7l-1.0.tar.gz.sha512) This file is required to check the integrity of the above tar archive. It is not mandatory but it is strongly advised to download this file and check the tar archive integrity
* [optional] Open a terminal window
* [optional] Check the integrity of the tar archive by issuing this command: `sha512sum --check hummingbird-armv7l-1.0.tar.gz.sha512`
* [optional] Make sure the command responds with `hummingbird-armv7l-1.0.tar.gz: OK`
* Change your current directory to a convenient place, such as your home directory. This can be done by issuing the command `cd ~`
* Extract the tar archive by issuing this command on your terminal window: `tar xvf hummingbird-armv7l-1.0.tar.gz`
* A new directory will be created: `hummingbird-armv7l-1.0`'
* Move into this new directory with command `cd hummingbird-armv7l-1.0`
* [optional] Check the integrity of the binary file `hummingbird`. Issue this command from your terminal window: `sha512sum --check hummingbird.sha512`
* [optional] Make sure the command responds with `hummingbird: OK`
* [optional] Check dynamic library availability. Issue the command `ldd hummingbird` and make sure all the required dynamic libraries are available. No line of the output must contain "not found"
* the Raspberry/Raspbian/ARM32 client is now ready to be used and possibly copied to a different directory of your system, such as `/usr/bin` or `/usr/local/bin`

**Please note hummingbird needs root privileges. Your user must therefore be included in your system's "sudoers"**

 
## Raspberry - Linux ARM 64 bit Installation

* Download [hummingbird-aarch64-1.0.tar.gz](https://gitlab.com/AirVPN/hummingbird/blob/master/binary/hummingbird-linux-aarch64-1.0.tar.gz)
* [optional] Download [hummingbird-aarch64-1.0.tar.gz.sha512](https://gitlab.com/AirVPN/hummingbird/blob/master/binary/hummingbird-linux-aarch64-1.0.tar.gz.sha512) This file is required to check the integrity of the above tar archive. It is not mandatory but it is strongly advised to download this file and check the tar archive integrity
* [optional] Open a terminal window
* [optional] Check the integrity of the tar archive by issuing this command: `sha512sum --check hummingbird-aarch64-1.0.tar.gz.sha512`
* [optional] Make sure the command responds with "``hummingbird-aarch64--1.0-RC2.tar.gz: OK`
* Change your current directory to a convenient place, such as your home directory. This can be done by issuing the command `cd ~`
* Extract the tar archive by issuing this command on your terminal window: `tar xvf hummingbird-aarch64-1.0.tar.gz`
* A new directory will be created: `hummingbird-aarch64-1.0`
* Move into this new directory with command `cd hummingbird-aarch64-1.0`
* [optional] Check the integrity of the binary file `hummingbird`. Issue this command from your terminal window: `sha512sum --check hummingbird.sha512`
* [optional] Make sure the command responds with `hummingbird: OK`
* [optional] Check dynamic library availability. Issue the command `ldd hummingbird` and make sure all the required dynamic libraries are available. No line of the output must contain "not found"
* The Raspberry/ARM64 client is now ready to be used and possibly copied to a different directory of your system, such as `/usr/bin` or `/usr/local/bin`

**Please note hummingbird needs root privileges. Your user must therefore be included in your system's "sudoers"**

 
## macOS Installation

* Download [hummingbird-macos-1.0.tar.gz](https://gitlab.com/AirVPN/hummingbird/blob/master/binary/hummingbird-macos-1.0.tar.gz)
* [optional] Download [hummingbird-macos-1.0.tar.gz.sha512](https://gitlab.com/AirVPN/hummingbird/blob/master/binary/hummingbird-macos-1.0.tar.gz.sha512) This file is required to check the integrity of the above tar archive. It is not mandatory but it is strongly advised to download this file and check the tar archive integrity
* [optional] Open a terminal window
* [optional] Check the integrity of the tar archive by issuing this command: `shasum -a 512 -c hummingbird-macos-1.0.tar.gz.sha512`
* [optional] Make sure the command responds with `hummingbird-macos-1.0.tar.gz: OK`
* Change your current directory to a convenient place, such as your home directory. This can be done by issuing the command `cd ~`
* Extract the tar archive by issuing this command on your terminal window: `tar xvf hummingbird-macos-1.0.tar.gz`
* A new directory will be created: `hummingbird-macos-1.0`
* Move into this new directory by entering command `cd hummingbird-macos-1.0`
* [optional] Check the integrity of the binary file `hummingbird`. Issue this command from your terminal window: `shasum -a 512 -c hummingbird.sha512`
* [optional] Make sure the command responds with `hummingbird: OK`
* [optional] Check dynamic library availability. Issue the command `otool -L hummingbird` and make sure all the required dynamic libraries are available. No line of the output must contain "not found". **Please note `otool` is distributed with Xcode**
* the macOS client is now ready to be used and possibly copied to a different directory of your system, such as `/usr/bin` or `/usr/local/bin`

**Please note hummingbird needs root privileges.**

 
# Running the Hummingbird Client

Run `hummingbird` and display its help in order to become familiar with its options. From your terminal window issue this command:

>`sudo ./hummingbird --help`

After having entered your root account password, `hummingbird` responds with:
 
>`Hummingbird - AirVPN OpenVPN 3 Client 1.0 - 27 December 2019`  
>  
>`usage: ./hummingbird [options] <config-file> [extra-config-directives...]`  
>`--help, -h            : show this help page`  
>`--version, -v         : show version info`  
>`--eval, -e            : evaluate profile only (standalone)`  
>`--merge, -m           : merge profile into unified format (standalone)`  
>`--username, -u        : username`  
>`--password, -p        : password`  
>`--response, -r        : static response`  
>`--dc, -D              : dynamic challenge/response cookie`  
>`--cipher, -C          : encrypt packets with specific cipher algorithm (alg)`  
>`--proto, -P           : protocol override (udp|tcp)`  
>`--server, -s          : server override`  
>`--port, -R            : port override`  
>`--ncp-disable, -n     : disable negotiable crypto parameters`  
>`--network-lock, -N    : enable/disable network filter and lock (on|off, default on)`  
>`--gui-version, -E     : set custom gui version (text)`  
>`--ignore-dns-push, -i : ignore DNS push request and use system DNS settings`  
>`--ipv6, -6            : combined IPv4/IPv6 tunnel (yes|no|default)`  
>`--timeout, -t         : timeout`  
>`--compress, -c        : compression mode (yes|no|asym)`  
>`--pk-password, -z     : private key password`  
>`--tvm-override, -M    : tls-version-min override (disabled, default, tls_1_x)`  
>`--tcprof-override, -X : tls-cert-profile override (legacy, preferred, etc.)`  
>`--proxy-host, -y      : HTTP proxy hostname/IP`  
>`--proxy-port, -q      : HTTP proxy port`  
>`--proxy-username, -U  : HTTP proxy username`  
>`--proxy-password, -W  : HTTP proxy password`  
>`--proxy-basic, -B     : allow HTTP basic auth`  
>`--alt-proxy, -A       : enable alternative proxy module`  
>`--dco, -d             : enable data channel offload`  
>`--cache-password, -H  : cache password`  
>`--no-cert, -x         : disable client certificate`  
>`--def-keydir, -k      : default key direction ('bi', '0', or '1')`  
>`--force-aes-cbc, -f   : force AES-CBC ciphersuites`  
>`--ssl-debug           : SSL debug level`  
>`--google-dns, -g      : enable Google DNS fallback`  
>`--auto-sess, -a       : request autologin session`  
>`--auth-retry, -Y      : retry connection on auth failure`  
>`--persist-tun, -j     : keep TUN interface open across reconnects`  
>`--peer-info, -I       : peer info key/value list in the form K1=V1,K2=V2,...`  
>`--gremlin, -G         : gremlin info (send_delay_ms, recv_delay_ms, send_drop_prob, recv_drop_prob)`  
>`--epki-ca             : simulate external PKI cert supporting intermediate/root certs`  
>`--epki-cert           : simulate external PKI cert`  
>`--epki-key            : simulate external PKI private key`  
>`--recover-network     : recover network settings after a crash or unexpected exit`  
>  
>`Open Source Project by AirVPN (https://airvpn.org)`  
>  
>`Linux and macOS design, development and coding: ProMIND`  
>  
>`Special thanks to the AirVPN community for the valuable help,`  
>`support, suggestions and testing.`  


Hummingbird needs a valid OpenVPN profile in order to connect to a server. You can create an OpenVPN profile by using the config generator available at AirVPN website in your account's [Client Area](https://airvpn.org/generator/)

#### Start a connection

>`sudo ./hummingbird your_openvpn_file.ovpn`

#### Stop a connection

Type `CTRL+C` in the terminal window where hummingbird is running. The client will initiate the disconnection process and will restore your original network settings according to your options.


#### Start a connection with a specific cipher

>`sudo ./hummingbird --ncp-disable --cipher CHACHA20-POLY1305 your_openvpn_file.ovpn`

**Please note**: in order to properly work, the server you are connecting to must support the cipher specified with the `--cipher` option. If you wish to use `CHACHA20-POLY1305` cipher, you can find AirVPN servers supporting it in [our real time servers monitor](https://airvpn.org/status): they are marked in yellow as "Experimental ChaCha20".

#### Disable the network filter and lock

>`sudo ./hummingbird --network-lock off your_openvpn_file.ovpn`

#### Ignore the DNS servers pushed by the VPN server

>`sudo ./hummingbird --ignore-dns-push your_openvpn_file.ovpn`

**Please note**: the above options can be combined together according to their use and function.

 
## Network Filter and Lock

Hummingbird's network filter and lock natively uses `iptables`, `nftables` and `pf` in order to provide a "best effort leak prevention". Hummingbird will automatically detect and use the infrastructure available on your system. **Please note**: Linux services `firewalld` and `ufw` may interfere with the hummingbird's network filter and lock and you are strongly advised to not issue any firewall related command while the VPN connection is active.


## DNS Management in Linux

Hummingbird currently supports both `resolv.conf` and `systemd-resolved` service. It is also aware of Network Manager, in case it is running. While the client is running, you are strongly advised to not issue any resolved related command (such as `resolvectl`) or change the `resolv.conf` file in order to make sure the system properly uses DNS pushed by the VPN server. **Please note**: DNS system settings are not changed in case the client has been started with `--ignore-dns-push`. In this specific case, the connection will use your system's DNS.

Furthermore, please note that if your network interfaces are managed by Network Manager, DNS settings might be changed under peculiar circumstances during a VPN connection, even when DNS push had been previously accepted.


## DNS Management in macOS

DNS setting and management is done through OpenVPN 3 native support


## Recover Your Network Settings

In case hummingbird crashes or it is killed by the user (i.e. ``kill -9 `pidof hummingbird` ``) as well as in case of system reboot while the connection is active, the system will keep and use all the network settings determined by the client; therefore, your network connection will not work as expected, every connection is refused and the system will seem to be "network locked". To restore and recover your system network, you can use the client with the `--recover-network` option.

>`sudo ./hummingbird --recover-network`

Please note in case of crash or unexpected exit, when you subsequently run hummingbird it will warn you about the unexpected exit and will require you to run it again with the `--recover-network` option. It will also refuse to start any connection until the network has been properly restored and recovered. 


# Compile Hummingbird from Sources

In order to build `hummingbird` from sources, you need the following dependencies:

* [OpenVPN 3 AirVPN fork](https://github.com/AirVPN/openvpn3-airvpn) (at least version 3.6.1)
* [asio](https://github.com/chriskohlhoff/asio)
* [mbedTLS 2.6.13](https://tls.mbed.org/download)
* [LZ4 library](https://github.com/lz4/lz4)
* [LZMA library](https://www.7-zip.org/sdk.html)
* [Linux] GCC development suite
* [macOS] clang/XCode development suite

Clone `hummingbird` repository into your computer:

>`git clone https://gitlab.com/AirVPN/hummingbird`

Move into the project's directory:

>`cd hummingbird`


## Build Linux Dynamic Binary

Edit `build.sh` script and set `INC_DIR`, `OPENVPN3` and `ASIO` variables according to your system configuration

Run the build shell script:

>`sh build.sh`

The script will compile the project and create `hummingbird` binary in the current directory.


## Build Linux - ARM and macOS Static Binary

Edit `build-static.sh` script and set `INC_DIR`, `OPENVPN3` and `ASIO` variables according to your system configuration. Also set `STATIC_LIB_DIR` and `SSL_LIB_DIR` according to your system architecture.

Run the build shell script:

>`sh build-static.sh`

The script will create a `hummingbird` static binary file according to your system and will also create the associated distribution compressed tarball file in the current directory. To install the binary in your system, please refer to the installation instructions provided above.


***

Hummingbird is an open source project by [AirVPN](https://airvpn.org)  
  
Linux and macOS design, development and coding: ProMIND  
  
Special thanks to the AirVPN community for the valuable help, support, suggestions and testing.  

OpenVPN is Copyright (C) 2012-2017 OpenVPN Inc. All rights reserved.

Hummingbird is released and licensed under the [GNU General Public License Version 3 (GPLv3)](https://gitlab.com/AirVPN/hummingbird/blob/master/LICENSE.md)

