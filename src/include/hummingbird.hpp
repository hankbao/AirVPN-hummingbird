/*
 * hummingbird.hpp
 *
 * This file is part of AirVPN's Linux/macOS OpenVPN Client software.
 * Copyright (C) 2019 AirVPN (support@airvpn.org) / https://airvpn.org
 *
 * Developed by ProMIND
 *
 * This is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Eddie. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef HUMMINGBIRD_HPP
#define HUMMINGBIRD_HPP

#include "localnetwork.hpp"
#include <client/ovpncli.cpp>

#define HUMMINGBIRD_NAME            "Hummingbird - AirVPN OpenVPN 3 Client"
#define HUMMINGBIRD_VERSION         "1.0"
#define HUMMINGBIRD_RELEASE_DATE    "27 December 2019"
#define HUMMINGBIRD_FULL_NAME       HUMMINGBIRD_NAME " " HUMMINGBIRD_VERSION
#define RESOURCE_DIRECTORY          "/etc/airvpn"
#define HUMMINGBIRD_LOCK_FILE       RESOURCE_DIRECTORY "/hummingbird.lock"
#define RESOLVDOTCONF_BACKUP        RESOURCE_DIRECTORY "/resolv.conf.airvpnbackup"
#define SYSTEM_DNS_BACKUP_FILE      RESOURCE_DIRECTORY "/systemdns.airvpnbackup"

#if defined(OPENVPN_PLATFORM_LINUX)

    // use SITNL by default
    #ifndef OPENVPN_USE_IPROUTE2

        #define OPENVPN_USE_SITNL

    #endif

    #include <openvpn/tun/linux/client/tuncli.hpp>

    // we use a static polymorphism and define a
    // platform-specific TunSetup class, responsible
    // for setting up tun device

    #define TUN_CLASS_SETUP TunLinuxSetup::Setup<TUN_LINUX>

#elif defined(OPENVPN_PLATFORM_MAC)

    #include <openvpn/tun/mac/client/tuncli.hpp>

    #define TUN_CLASS_SETUP TunMac::Setup

#endif

enum IPClass
{
    v4,
    v6,
    Unknown
};

using namespace openvpn;

class ClientBase : public ClientAPI::OpenVPNClient, public LocalNetwork
{
    protected:

    NetFilter *netFilter = NULL;

#if defined(OPENVPN_PLATFORM_LINUX)
    DNSManager *dnsManager = NULL;
#endif

    std::vector<IPEntry> dnsTable;
    std::vector<IPEntry> systemDnsTable;
    std::vector<IPEntry> remoteServerIpList;
    TUN_CLASS_SETUP::Config tunnelConfig;
    ClientAPI::Config config;
    ClientAPI::EvalConfig evalConfig;
    bool dnsHasBeenPushed = false;
    bool networkLockEnabled = true;
    bool dnsPushIgnored = false;

    public:

    ClientBase();
    ~ClientBase();

    bool tun_builder_new() override;
    int tun_builder_establish() override;
    bool tun_builder_add_address(const std::string& address, int prefix_length, const std::string& gateway, bool ipv6, bool net30) override;
    bool tun_builder_add_route(const std::string& address, int prefix_length, int metric, bool ipv6) override;
    bool tun_builder_reroute_gw(bool ipv4, bool ipv6, unsigned int flags) override;
    bool tun_builder_set_remote_address(const std::string& address, bool ipv6) override;
    bool tun_builder_set_session_name(const std::string& name) override;
    bool tun_builder_add_dns_server(const std::string& address, bool ipv6) override;
    void tun_builder_teardown(bool disconnect) override;
    bool socket_protect(int socket, std::string remote, bool ipv6) override;
    bool ignore_dns_push() override;

    void setConfig(ClientAPI::Config c);
    ClientAPI::Config getConfig();
    void setEvalConfig(ClientAPI::EvalConfig e);
    ClientAPI::EvalConfig getEvalConfig();
    void enableNetworkLock(bool enable);
    bool isNetworkLockEnabled();
    void ignoreDnsPush(bool ignore);
    bool isDnsPushIgnored();

    private:

    TUN_CLASS_SETUP::Ptr tunnelSetup = new TUN_CLASS_SETUP();
    TunBuilderCapture tunnelBuilderCapture;
};

class Client : public ClientBase
{
    public:

    enum ClockTickAction
    {
        CT_UNDEF,
        CT_STOP,
        CT_RECONNECT,
        CT_PAUSE,
        CT_RESUME,
        CT_STATS,
    };

    Client();
    ~Client();

    bool is_dynamic_challenge() const;
    std::string dynamic_challenge_cookie();

    std::string epki_ca;
    std::string epki_cert;

#if defined(USE_MBEDTLS)

    MbedTLSPKI::PKContext epki_ctx; // external PKI context

#endif

    void set_clock_tick_action(const ClockTickAction action);
    void print_stats();

    void restoreNetworkSettings(bool stdOutput = false);

#ifdef OPENVPN_REMOTE_OVERRIDE

    void set_remote_override_cmd(const std::string& cmd);

#endif

    private:

    virtual void event(const ClientAPI::Event& ev) override;
    virtual void log(const ClientAPI::LogInfo& log) override;
    virtual void clock_tick() override;
    virtual void external_pki_cert_request(ClientAPI::ExternalPKICertRequest& certreq) override;
    virtual void external_pki_sign_request(ClientAPI::ExternalPKISignRequest& signreq) override;

    static int rng_callback(void *arg, unsigned char *data, size_t len);

    virtual bool pause_on_connection_timeout() override;

#ifdef OPENVPN_REMOTE_OVERRIDE

    virtual bool remote_override_enabled() override;
    virtual void remote_override(ClientAPI::RemoteOverride& ro);

#endif

    bool addServer(IPClass ipclass, std::string serverIP);

    std::mutex log_mutex;
    std::string dc_cookie;
    RandomAPI::Ptr rng;      // random data source for epki
    volatile ClockTickAction clock_tick_action = CT_UNDEF;

#ifdef OPENVPN_REMOTE_OVERRIDE

    std::string remote_override_cmd;

#endif

};

#endif
