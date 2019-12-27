/*
 * hummingbird.cpp
 *
 * This file is part of AirVPN's hummingbird Linux/macOS OpenVPN Client software.
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

#include <stdlib.h>
#include <string>
#include <iostream>
#include <algorithm>
#include <thread>
#include <memory>
#include <mutex>
#include <vector>
#include <dirent.h>
#include <errno.h>
#include <resolv.h>
#include <arpa/inet.h>
#include "include/execproc.h"
#include "include/netfilter.hpp"
#include <openvpn/common/platform.hpp>

#define USE_TUN_BUILDER

#if defined(OPENVPN_PLATFORM_LINUX)

    #include "include/dnsmanager.hpp"
    #include "include/loadmod.h"

    bool load_linux_module(const char *module_name, const char *module_params, bool stdOutput = false);

#endif

#ifdef OPENVPN_PLATFORM_MAC

    #include <CoreFoundation/CFBundle.h>
    #include <ApplicationServices/ApplicationServices.h>
    #include <SystemConfiguration/SystemConfiguration.h>

#endif

// don't export core symbols
#define OPENVPN_CORE_API_VISIBILITY_HIDDEN

#define OPENVPN_DEBUG_VERBOSE_ERRORS
// #define OPENVPN_DEBUG_CLIPROTO

#include "include/hummingbird.hpp"

// If enabled, don't direct ovpn3 core logging to
// ClientAPI::OpenVPNClient::log() virtual method.
// Instead, logging will go to LogBaseSimple::log().
// In this case, make sure to define:
//   LogBaseSimple log;
// at the top of your main() function to receive
// log messages from all threads.
// Also, note that the OPENVPN_LOG_GLOBAL setting
// MUST be consistent across all compilation units.

#ifdef OPENVPN_USE_LOG_BASE_SIMPLE

    #define OPENVPN_LOG_GLOBAL // use global rather than thread-local  object pointer

    #include <openvpn/log/logbasesimple.hpp>

#endif

// should be included before other openvpn includes,
// with the exception of openvpn/log includes

#include <openvpn/common/exception.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/signal.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/getopt.hpp>
#include <openvpn/common/getpw.hpp>
#include <openvpn/common/cleanup.hpp>
#include <openvpn/time/timestr.hpp>
#include <openvpn/ssl/peerinfo.hpp>
#include <openvpn/ssl/sslchoose.hpp>

#ifdef OPENVPN_REMOTE_OVERRIDE

    #include <openvpn/common/process.hpp>

#endif

#if defined(USE_MBEDTLS)

    #include <openvpn/mbedtls/util/pkcs1.hpp>

#endif

bool init_check(void);
bool clean_up(void);
void aboutDevelopmentCredits(void);

using namespace openvpn;

namespace
{
    OPENVPN_SIMPLE_EXCEPTION(usage);
}

// ClientBase class

ClientBase::ClientBase()
{
    netFilter = new NetFilter(RESOURCE_DIRECTORY);

#if defined(OPENVPN_PLATFORM_LINUX)

    dnsManager = new DNSManager(RESOLVDOTCONF_BACKUP);

#endif

    dnsHasBeenPushed = false;
    networkLockEnabled = true;
    dnsPushIgnored = false;
}

ClientBase::~ClientBase()
{
    if(netFilter != NULL)
        delete netFilter;

#if defined(OPENVPN_PLATFORM_LINUX)

    if(dnsManager != NULL)
        delete dnsManager;

#endif
}

bool ClientBase::tun_builder_new()
{
    tunnelBuilderCapture.tun_builder_set_mtu(1500);

    return true;
}

int ClientBase::tun_builder_establish()
{
    if(!tunnelSetup)
        tunnelSetup.reset(new TUN_CLASS_SETUP());

    tunnelConfig.layer = Layer(Layer::Type::OSI_LAYER_3);

    // no need to add bypass routes on establish since we do it on socket_protect

    tunnelConfig.add_bypass_routes_on_establish = false;

    return tunnelSetup->establish(tunnelBuilderCapture, &tunnelConfig, nullptr, std::cout);
}

bool ClientBase::tun_builder_add_address(const std::string& address, int prefix_length, const std::string& gateway, bool ipv6, bool net30)
{
    return tunnelBuilderCapture.tun_builder_add_address(address, prefix_length, gateway, ipv6, net30);
}

bool ClientBase::tun_builder_add_route(const std::string& address, int prefix_length, int metric, bool ipv6)
{
    return tunnelBuilderCapture.tun_builder_add_route(address, prefix_length, metric, ipv6);
}

bool ClientBase::tun_builder_reroute_gw(bool ipv4, bool ipv6, unsigned int flags)
{
    return tunnelBuilderCapture.tun_builder_reroute_gw(ipv4, ipv6, flags);
}

bool ClientBase::tun_builder_set_remote_address(const std::string& address, bool ipv6)
{
    return tunnelBuilderCapture.tun_builder_set_remote_address(address, ipv6);
}

bool ClientBase::tun_builder_set_session_name(const std::string& name)
{
    return tunnelBuilderCapture.tun_builder_set_session_name(name);
}

bool ClientBase::tun_builder_add_dns_server(const std::string& address, bool ipv6)
{
    std::ostringstream os;
    IPEntry dnsEntry;
    NetFilter::IP filterIP;
    std::string dnsFilterIP;

    if(dnsPushIgnored == false)
    {
        os.str("");

        os << "VPN Server has pushed ";

        if(ipv6)
            os << "IPv6";
        else
            os << "IPv4";

        os << " DNS server " << address;

        OPENVPN_LOG(os.str());

        dnsEntry.address = address;
        dnsEntry.ipv6 = ipv6;

        dnsTable.push_back(dnsEntry);

        dnsHasBeenPushed = true;

        dnsFilterIP = address;

        if(ipv6)
        {
            filterIP = NetFilter::IP::v6;

            dnsFilterIP += "/128";
        }
        else
        {
            filterIP = NetFilter::IP::v4;

            dnsFilterIP += "/32";
        }

        netFilter->commitAllowRule(filterIP, NetFilter::Direction::OUTPUT, "", NetFilter::Protocol::ANY, "", 0, dnsFilterIP, 0);
    }

#if defined(OPENVPN_PLATFORM_LINUX)

    DNSManager::Error retval;

    if(dnsPushIgnored == false)
    {
        os.str("");

        retval = dnsManager->addAddressToResolvDotConf(address, ipv6);

        if(retval == DNSManager::Error::OK)
        {
            os << "Setting pushed ";

            if(ipv6)
                os << "IPv6";
            else
                os << "IPv4";

            os << " DNS server " << address << " in resolv.conf";
        }
        else if(retval == DNSManager::Error::RESOLV_DOT_CONF_OPEN_ERROR)
        {
            os << "ERROR: Cannot open resolv.conf";
        }
        else if(retval == DNSManager::Error::RESOLV_DOT_CONF_RENAME_ERROR)
        {
            os << "ERROR: Cannot create a backup copy of resolv.conf";
        }
        else if(retval == DNSManager::Error::RESOLV_DOT_CONF_WRITE_ERROR)
        {
            os << "ERROR: Cannot write in resolv.conf";
        }
        else
        {
            os << "ERROR: resolv.conf generic error";
        }

        OPENVPN_LOG(os.str());

        if(dnsManager->systemHasResolved() && !dnsManager->systemHasNetworkManager())
        {
            for(std::string interface : localInterface)
            {
                os.str("");

                retval = dnsManager->addAddressToResolved(interface, address.c_str(), ipv6);

                if(retval == DNSManager::Error::OK)
                {
                    os << "Setting pushed ";

                    if(ipv6)
                        os << "IPv6";
                    else
                        os << "IPv4";

                    os << " DNS server " << address << " for interface " << interface << " via systemd-resolved";
                }
                else if(retval == DNSManager::Error::RESOLVED_IS_NOT_AVAILABLE)
                {
                    os << "ERROR systemd-resolved is not available on this system";
                }
                else if(retval == DNSManager::Error::RESOLVED_ADD_DNS_ERROR)
                {
                    os << "ERROR systemd-resolved: Failed to add DNS server " << address << " for interface " << interface;
                }
                else if(retval == DNSManager::Error::NO_RESOLVED_COMMAND)
                {
                    os << "ERROR systemd-resolved: resolvectl or systemd-resolve command not found";
                }
                else
                {
                    os << "ERROR systemd-resolved: Unknown error while adding DNS server " << address << " for interface " << interface;
                }

                OPENVPN_LOG(os.str());
            }
        }
    }
    else
    {
        os.str("");

        os << "WARNING: ignoring server DNS push request for address " << address;

        OPENVPN_LOG(os.str());
    }

#endif

    return tunnelBuilderCapture.tun_builder_add_dns_server(address, ipv6);
}

void ClientBase::tun_builder_teardown(bool disconnect)
{
    std::ostringstream os;

    auto os_print = Cleanup([&os](){ OPENVPN_LOG_STRING(os.str()); });

    tunnelSetup->destroy(os);
}

bool ClientBase::socket_protect(int socket, std::string remote, bool ipv6)
{
    (void)socket;
    std::ostringstream os;

    auto os_print = Cleanup([&os](){ OPENVPN_LOG_STRING(os.str()); });

    return tunnelSetup->add_bypass_route(remote, ipv6, os);
}

bool ClientBase::ignore_dns_push()
{
    return dnsPushIgnored;
}

void ClientBase::setConfig(ClientAPI::Config c)
{
    config = c;
}

ClientAPI::Config ClientBase::getConfig()
{
    return config;
}

void ClientBase::setEvalConfig(ClientAPI::EvalConfig e)
{
    evalConfig = e;
}

ClientAPI::EvalConfig ClientBase::getEvalConfig()
{
    return evalConfig;
}

void ClientBase::enableNetworkLock(bool enable)
{
    networkLockEnabled = enable;
}

bool ClientBase::isNetworkLockEnabled()
{
    return networkLockEnabled;
}

void ClientBase::ignoreDnsPush(bool ignore)
{
    dnsPushIgnored = ignore;
}

bool ClientBase::isDnsPushIgnored()
{
    return dnsPushIgnored;
}

// Client class

Client::Client()
{
}

Client::~Client()
{
}

bool Client::is_dynamic_challenge() const
{
    return !dc_cookie.empty();
}

std::string Client::dynamic_challenge_cookie()
{
    return dc_cookie;
}

void Client::set_clock_tick_action(const ClockTickAction action)
{
    clock_tick_action = action;
}

void Client::print_stats()
{
    const int n = stats_n();
    std::vector<long long> stats = stats_bundle();

    std::cout << "STATS:" << std::endl;

    for(int i = 0; i < n; ++i)
    {
	    const long long value = stats[i];

        if(value)
	        std::cout << "  " << stats_name(i) << " : " << value << std::endl;
    }
}

#ifdef OPENVPN_REMOTE_OVERRIDE

    void Client::set_remote_override_cmd(const std::string& cmd)
    {
        remote_override_cmd = cmd;
    }

#endif

void Client::event(const ClientAPI::Event& ev)
{
    std::ostringstream os;

    std::cout << date_time() << " EVENT: " << ev.name;

    if(!ev.info.empty())
        std::cout << ' ' << ev.info;

    if(ev.fatal)
        std::cout << " [FATAL-ERR]";
    else if(ev.error)
        std::cout << " [ERR]";

    std::cout << std::endl;

    if(ev.name == "RESOLVE")
    {
        NetFilter::Mode filterMode;
        std::string serverIP, filterServerIP, protocol;
        std::ofstream systemDNSDumpFile;
        struct addrinfo ipinfo, *ipres = NULL, *current_ai;
        int aires;
        char resip[64];
        IPClass ipclass;
        NetFilter::IP filterIP;
        IPEntry ipEntry;

#if defined(OPENVPN_PLATFORM_LINUX)

        if(dnsPushIgnored == false)
        {
            if(dnsManager->systemHasNetworkManager())
            {
                os.str("");

                os << "WARNING: NetworkManager is running on this system and may interfere with DNS management and cause DNS leaks";

                OPENVPN_LOG(os.str());
            }

            if(dnsManager->systemHasResolved())
            {
                os.str("");

                os << "WARNING: systemd-resolved is running on this system and may interfere with DNS management and cause DNS leaks";

                OPENVPN_LOG(os.str());
            }
        }

#endif

        // save system DNS

        res_ninit(&_res);

        dnsTable.clear();
        systemDnsTable.clear();

        systemDNSDumpFile.open(SYSTEM_DNS_BACKUP_FILE);

        for(int i=0; i < MAXNS; i++)
        {
            if(_res.nsaddr_list[i].sin_addr.s_addr > 0)
            {
                ipEntry.address = inet_ntoa(_res.nsaddr_list[i].sin_addr);

                if(_res.nsaddr_list[i].sin_family == AF_INET)
                    ipEntry.ipv6 = false;
                else
                    ipEntry.ipv6 = true;

                systemDnsTable.push_back(ipEntry);

                systemDNSDumpFile << ipEntry.address << std::endl;
            }
        }

        systemDNSDumpFile.close();

        if(networkLockEnabled == true)
        {
            os.str("");

            filterMode = netFilter->getMode();

            if(filterMode != NetFilter::Mode::AUTO && filterMode != NetFilter::Mode::UNKNOWN)
                os << "Network filter and lock is using " << netFilter->getModeDescription();
            else
                os << "Network filter and lock disabled. No supported backend found.";

            OPENVPN_LOG(os.str());

#if defined(OPENVPN_PLATFORM_LINUX)

            if(filterMode == NetFilter::Mode::IPTABLES)
            {
                load_linux_module("iptable_filter", "");
                load_linux_module("iptable_nat", "");
                load_linux_module("iptable_mangle", "");
                load_linux_module("iptable_security", "");
                load_linux_module("iptable_raw", "");

                load_linux_module("ip6table_filter", "");
                load_linux_module("ip6table_nat", "");
                load_linux_module("ip6table_mangle", "");
                load_linux_module("ip6table_security", "");
                load_linux_module("ip6table_raw", "");
            }
            else if(filterMode == NetFilter::Mode::NFTABLES)
            {
                load_linux_module("nf_tables", "");
            }

            if(netFilter->isFirewalldRunning())
            {
                os.str("");

                os << "WARNING: firewalld is running on this system and may interfere with network filter and lock";

                OPENVPN_LOG(os.str());
            }

            if(netFilter->isUfwRunning())
            {
                os.str("");

                os << "WARNING: ufw is running on this system and may interfere with network filter and lock";

                OPENVPN_LOG(os.str());
            }

#endif

            os.str("");

            if(netFilter->init())
                os << "Network filter successfully initialized";
            else
                os << "ERROR: Cannot initialize network filter";

            OPENVPN_LOG(os.str());

            for(IPEntry ip : localIPaddress)
            {
                os.str("");

                os << "Local IPv";

                if(ip.ipv6 == true)
                    os << "6";
                else
                    os << "4";

                os << " address " << ip.address;

                OPENVPN_LOG(os.str());
            }

            for(std::string interface : localInterface)
            {
                os.str("");

                os << "Local interface " << interface;

                OPENVPN_LOG(os.str());
            }

            netFilter->setup(loopbackInterface);

            os.str("");

            os << "Setting up network filter and lock";

            OPENVPN_LOG(os.str());

            // Allow system DNS to pass through network filter. It may be later denied by DNS push

            for(IPEntry dns : systemDnsTable)
            {
                if(dns.ipv6 == true)
                    filterIP = NetFilter::IP::v6;
                else
                    filterIP = NetFilter::IP::v4;

                netFilter->addAllowRule(filterIP, NetFilter::Direction::OUTPUT, "", NetFilter::Protocol::ANY, "", 0, dns.address, 0);

                os.str("");

                os << "Allowing system DNS " << dns.address << " to pass through the network filter";

                OPENVPN_LOG(os.str());
            }

            // Adding profile's remote entries to network filter

            if(evalConfig.remoteList.size() > 1)
            {
                os.str("");

                os << "OpenVPN profile has multiple remote directives. Temporarily adding remote servers to network filter.";

                OPENVPN_LOG(os.str());
            }

            remoteServerIpList.clear();

            for(ClientAPI::RemoteEntry remoteEntry : evalConfig.remoteList)
            {
                memset(&ipinfo, 0, sizeof(ipinfo));

                ipinfo.ai_family = PF_UNSPEC;
                ipinfo.ai_flags = AI_NUMERICHOST;
                ipclass = IPClass::Unknown;

                aires = getaddrinfo(remoteEntry.server.c_str(), NULL, &ipinfo, &ipres);

                if(aires || ipres == NULL)
                {
                    ipclass = IPClass::Unknown;
                }
                else
                {
                    serverIP = remoteEntry.server;

                    switch(ipres->ai_family)
                    {
                        case AF_INET:
                        {
                            ipclass = IPClass::v4;
                        }
                        break;

                        case AF_INET6:
                        {
                            ipclass = IPClass::v6;
                        }
                        break;

                        default:
                        {
                            ipclass = IPClass::Unknown;
                        }
                    }
                }

                if(ipres != NULL)
                {
                    freeaddrinfo(ipres);

                    ipres = NULL;
                }

                if(ipclass == IPClass::Unknown)
                {
                    memset(&ipinfo, 0, sizeof(ipinfo));

                    ipinfo.ai_family = PF_UNSPEC;

                    os.str("");

                    if(getaddrinfo(remoteEntry.server.c_str(), NULL, &ipinfo, &ipres) == 0)
                    {
                        for(current_ai = ipres; current_ai != NULL; current_ai = current_ai->ai_next)
	                    {
                            getnameinfo(current_ai->ai_addr, current_ai->ai_addrlen, resip, sizeof(resip), NULL, 0, NI_NUMERICHOST);

                            serverIP = resip;

                            switch(current_ai->ai_family)
                            {
                                case AF_INET:
                                {
                                    protocol = "4";
                                    ipclass = IPClass::v4;
                                }
                                break;

                                case AF_INET6:
                                {
                                    protocol = "6";
                                    ipclass = IPClass::v6;
                                }
                                break;

                                default:
                                {
                                    protocol = "??";
                                    ipclass = IPClass::Unknown;
                                }
                            }

                            if(addServer(ipclass, serverIP) == true)
                            {
                                os.str("");

                                os << "Resolved server " << remoteEntry.server << " into IPv" << protocol<< " " << serverIP;

                                OPENVPN_LOG(os.str());;

                                os.str("");

                                os << "Adding IPv" << protocol << " server " << serverIP << " to network filter";

                                OPENVPN_LOG(os.str());
                            }
                        }
                    }
                    else
                    {
                        ipclass = IPClass::Unknown;
                        serverIP = "";

                        os.str("");

                        os << "WARNING: Cannot resolve " << remoteEntry.server;

                        OPENVPN_LOG(os.str());
                    }

                    if(ipres != NULL)
                    {
                        freeaddrinfo(ipres);

                        ipres = NULL;
                    }
                }
                else
                {
                    if(addServer(ipclass, serverIP) == true)
                    {
                        os.str("");

                        os << "Adding IPv";

                        if(ipclass == IPClass::v4)
                            os << "4";
                        else
                            os << "6";

                        os << " server " << serverIP << " to network filter";

                        OPENVPN_LOG(os.str());
                    }
                }
            }

            os.str("");

            if(netFilter->commitRules() == true)
                os << "Network filter and lock successfully activated";
            else
                os << "ERROR: Cannot activate network filter and lock";

            OPENVPN_LOG(os.str());
        }
        else
        {
            os.str("");

            os << "WARNING: Network filter and lock is disabled";

            OPENVPN_LOG(os.str());
        }
    }
    else if(ev.name == "DYNAMIC_CHALLENGE")
    {
	    dc_cookie = ev.info;

	    ClientAPI::DynamicChallenge dc;

        if(ClientAPI::OpenVPNClient::parse_dynamic_challenge(ev.info, dc))
        {
            std::cout << "DYNAMIC CHALLENGE" << std::endl;
            std::cout << "challenge: " << dc.challenge << std::endl;
            std::cout << "echo: " << dc.echo << std::endl;
            std::cout << "responseRequired: " << dc.responseRequired << std::endl;
            std::cout << "stateID: " << dc.stateID << std::endl;
	    }
    }
    else if(ev.name == "CONNECTED")
    {
        NetFilter::IP filterIP;

        openvpn::ClientAPI::ConnectionInfo connectionInfo = connection_info();

        netFilter->addIgnoredInterface(tunnelConfig.iface_name);

#if defined(OPENVPN_PLATFORM_LINUX)

        DNSManager::Error retval;

        if(dnsManager->systemHasResolved() && !dnsManager->systemHasNetworkManager())
        {
            for(std::string interface : localInterface)
            {
                if(strncmp(connectionInfo.tunName.c_str(), interface.c_str(), connectionInfo.tunName.length()) == 0)
                {
                    for(IPEntry dns : dnsTable)
                    {
                        os.str("");

                        retval = dnsManager->addAddressToResolved(interface, dns.address.c_str(), dns.ipv6);

                        if(retval == DNSManager::Error::OK)
                        {
                            os << "Setting pushed ";

                            if(dns.ipv6)
                                os << "IPv6";
                            else
                                os << "IPv4";

                            os << " DNS server " << dns.address << " for interface " << interface << " via systemd-resolved";
                        }
                        else if(retval == DNSManager::Error::RESOLVED_IS_NOT_AVAILABLE)
                        {
                            os << "ERROR systemd-resolved is not available on this system";
                        }
                        else if(retval == DNSManager::Error::RESOLVED_ADD_DNS_ERROR)
                        {
                            os << "ERROR systemd-resolved: Failed to add DNS server " << dns.address << " for interface " << interface;
                        }
                        else if(retval == DNSManager::Error::NO_RESOLVED_COMMAND)
                        {
                            os << "ERROR systemd-resolved: resolvectl or systemd-resolve command not found";
                        }
                        else
                        {
                            os << "ERROR systemd-resolved: Unknown error while adding DNS server " << dns.address << " for interface " << interface;
                        }

                        OPENVPN_LOG(os.str());
                    }
                }
            }
        }

#endif

        if(dnsHasBeenPushed == true && networkLockEnabled == true && dnsPushIgnored == false)
        {
            os.str("");

            os << "Server has pushed its own DNS. Removing system DNS from network filter.";

            OPENVPN_LOG(os.str());

            for(IPEntry dns : systemDnsTable)
            {
                if(dns.ipv6 == true)
                    filterIP = NetFilter::IP::v6;
                else
                    filterIP = NetFilter::IP::v4;

                netFilter->commitRemoveAllowRule(filterIP, NetFilter::Direction::OUTPUT, "", NetFilter::Protocol::ANY, "", 0, dns.address, 0);

                os.str("");

                os << "System DNS " << dns.address << " is now rejected by the network filter";

                OPENVPN_LOG(os.str());
            }
        }

        if(networkLockEnabled == true && remoteServerIpList.size() > 1)
        {
            os.str("");

            os << "OpenVPN profile has multiple remote directives. Removing unused servers from network filter.";

            OPENVPN_LOG(os.str());

            for(IPEntry server : remoteServerIpList)
            {
                if(server.address != connectionInfo.serverIp)
                {
                    if(server.ipv6 == true)
                        filterIP = NetFilter::IP::v6;
                    else
                        filterIP = NetFilter::IP::v4;

                    netFilter->commitRemoveAllowRule(filterIP, NetFilter::Direction::OUTPUT, "", NetFilter::Protocol::ANY, "", 0, server.address, 0);

                    os.str("");

                    os << "Server IPv";

                    if(server.ipv6 == false)
                        os << "4";
                    else
                        os << "6";

                    os << " " << server.address << " has been removed from the network filter";

                    OPENVPN_LOG(os.str());
                }
            }
        }
    }
    else if(ev.name == "RECONNECTING")
    {
        restoreNetworkSettings();
    }
    else if(ev.name == "DISCONNECTED")
    {
        restoreNetworkSettings();
    }
}

bool Client::addServer(IPClass ipclass, std::string serverIP)
{
    std::string filterServerIP;
    IPEntry ipEntry;
    NetFilter::IP filterIPLevel;
    bool res = false;

    if(ipclass == IPClass::Unknown || serverIP == "" || serverIP == "0.0.0.0" || serverIP == "::/0")
        return false;

    ipEntry.address = serverIP;

    if(ipclass == IPClass::v4)
    {
        filterIPLevel = NetFilter::IP::v4;

        filterServerIP = serverIP + "/32";

        ipEntry.ipv6 = false;
    }
    else
    {
        filterIPLevel = NetFilter::IP::v6;

        filterServerIP = serverIP + "/128";

        ipEntry.ipv6 = true;
    }

    if(std::find(remoteServerIpList.begin(), remoteServerIpList.end(), ipEntry) == remoteServerIpList.end())
    {
        netFilter->addAllowRule(filterIPLevel, NetFilter::Direction::OUTPUT, "", NetFilter::Protocol::ANY, "", 0, filterServerIP, 0);

        remoteServerIpList.push_back(ipEntry);

        res = true;
    }

    return res;
}

void Client::restoreNetworkSettings(bool stdOutput)
{
    std::ostringstream os;

#if defined(OPENVPN_PLATFORM_LINUX)

    if(dnsPushIgnored == false)
    {
        DNSManager::Error retval;

        // restore resolv.conf

        retval = dnsManager->restoreResolvDotConf();

        os.str("");

        if(retval == DNSManager::Error::OK)
        {
            os << "Successfully restored DNS settings";
        }
        else if(retval == DNSManager::Error::RESOLV_DOT_CONF_OPEN_ERROR)
        {
            os << "ERROR: Cannot restore DNS settings. resolv.conf not found.";
        }
        else if(retval == DNSManager::Error::RESOLV_DOT_CONF_RESTORE_NOT_FOUND)
        {
            os << "ERROR: Backup copy of resolv.conf not found.";
        }
        else if(retval == DNSManager::Error::RESOLV_DOT_CONF_RESTORE_ERROR)
        {
            os << "ERROR: Cannot restore DNS settings.";
        }
        else
        {
            os << "ERROR: Cannot restore DNS settings. Unknown error.";
        }

        os << std::endl;

        if(stdOutput == false)
            OPENVPN_LOG_STRING(os.str());
        else
            std::cout << os.str();

        if(dnsManager->systemHasResolved() && !dnsManager->systemHasNetworkManager())
        {
            os.str("");

            retval = dnsManager->revertAllResolved();

            if(retval == DNSManager::Error::OK)
            {
                os << "Reverting systemd-resolved DNS settings";
            }
            else if(retval == DNSManager::Error::RESOLVED_IS_NOT_AVAILABLE)
            {
                os << "ERROR systemd-resolved is not available on this system";
            }
            else if(retval == DNSManager::Error::RESOLVED_REVERT_DNS_ERROR)
            {
                os << "ERROR systemd-resolved: Failed to revert DNS servers";
            }
            else if(retval == DNSManager::Error::NO_RESOLVED_COMMAND)
            {
                os << "ERROR systemd-resolved: resolvectl or systemd-resolve command not found";
            }
            else
            {
                os << "ERROR systemd-resolved: Unknown error while reverting DNS";
            }

            os << std::endl;

            if(stdOutput == false)
                OPENVPN_LOG_STRING(os.str());
            else
                std::cout << os.str();
        }
    }

#endif

#if defined(OPENVPN_PLATFORM_MAC)

    if(dnsPushIgnored == false)
    {
        std::ifstream systemDNSDumpFile;
        std::string line;
        SCDynamicStoreRef dnsStore;
        CFMutableArrayRef dnsArray;
        CFDictionaryRef dnsDictionary;
        CFArrayRef dnsList;
        CFIndex ndx, listItems;
        bool success = true;

        os.str("");

        if(access(SYSTEM_DNS_BACKUP_FILE, F_OK) == 0)
        {
            dnsArray = CFArrayCreateMutable(NULL, 0, NULL);

            systemDNSDumpFile.open(SYSTEM_DNS_BACKUP_FILE);

            while(std::getline(systemDNSDumpFile, line))
                CFArrayAppendValue(dnsArray, CFStringCreateWithFormat(NULL, NULL, CFSTR("%s"), line.c_str()));

            systemDNSDumpFile.close();

            dnsStore = SCDynamicStoreCreate(kCFAllocatorSystemDefault, CFSTR("AirVPNDNSRestore"), NULL, NULL);

            dnsDictionary = CFDictionaryCreate(NULL, (const void **)(CFStringRef []){ CFSTR("ServerAddresses") }, (const void **)&dnsArray, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

            dnsList = SCDynamicStoreCopyKeyList(dnsStore, CFSTR("Setup:/Network/(Service/.+|Global)/DNS"));

            listItems = CFArrayGetCount(dnsList);

            if(listItems > 0)
            {
                ndx = 0;

                while(ndx < listItems)
                {
                    success &= SCDynamicStoreSetValue(dnsStore, (CFStringRef)CFArrayGetValueAtIndex(dnsList, ndx), dnsDictionary);

                    ndx++;
                }
            }

            if(success == true)
                os << "Successfully restored system DNS.";
            else
                os << "ERROR: Error while restoring DNS settings.";
        }
        else
            os << "ERROR: Cannot restore DNS settings. Backup copy of system DNS not found.";

        os << std::endl;

        if(stdOutput == false)
            OPENVPN_LOG_STRING(os.str());
        else
            std::cout << os.str();
    }

#endif

    os.str("");

    if(networkLockEnabled == true)
    {
        if(netFilter->restore())
            os << "Network filter successfully restored";
        else
            os << "ERROR: Backup copy of network filter not found.";

        os << std::endl;

        if(stdOutput == false)
            OPENVPN_LOG_STRING(os.str());
        else
            std::cout << os.str();
    }
}

void Client::log(const ClientAPI::LogInfo& log)
{
    std::lock_guard<std::mutex> lock(log_mutex);

    std::cout << date_time() << ' ' << log.text << std::flush;
}

void Client::clock_tick()
{
    const ClockTickAction action = clock_tick_action;
    clock_tick_action = CT_UNDEF;

    switch(action)
    {
        case CT_STOP:
        {
            std::cout << "signal: CT_STOP" << std::endl;

            stop();
        }
	    break;

        case CT_RECONNECT:
        {
            std::cout << "signal: CT_RECONNECT" << std::endl;

            reconnect(0);
        }
	    break;

        case CT_PAUSE:
        {
            std::cout << "signal: CT_PAUSE" << std::endl;

            pause("clock-tick pause");
        }
	    break;

        case CT_RESUME:
        {
            std::cout << "signal: CT_RESUME" << std::endl;

            resume();
        }
	    break;

        case CT_STATS:
        {
            std::cout << "signal: CT_STATS" << std::endl;

            print_stats();
        }
	    break;

        default: break;
    }
}

void Client::external_pki_cert_request(ClientAPI::ExternalPKICertRequest& certreq)
{
    if(!epki_cert.empty())
    {
        certreq.cert = epki_cert;
        certreq.supportingChain = epki_ca;
    }
    else
    {
        certreq.error = true;
        certreq.errorText = "external_pki_cert_request not implemented";
    }
}

void Client::external_pki_sign_request(ClientAPI::ExternalPKISignRequest& signreq)
{
#if defined(USE_MBEDTLS)

    if(epki_ctx.defined())
    {
        try
        {
            // decode base64 sign request
            BufferAllocated signdata(256, BufferAllocated::GROW);
            base64->decode(signdata, signreq.data);

            // get MD alg
            const mbedtls_md_type_t md_alg = PKCS1::DigestPrefix::MbedTLSParse().alg_from_prefix(signdata);

            // log info
            OPENVPN_LOG("SIGN[" << PKCS1::DigestPrefix::MbedTLSParse::to_string(md_alg) << ',' << signdata.size() << "]: " << render_hex_generic(signdata));

            // allocate buffer for signature
            BufferAllocated sig(mbedtls_pk_get_len(epki_ctx.get()), BufferAllocated::ARRAY);

            // sign it
            size_t sig_size = 0;

            const int status = mbedtls_pk_sign(epki_ctx.get(), md_alg, signdata.c_data(), signdata.size(), sig.data(), &sig_size, rng_callback, this);

            if(status != 0)
	            throw Exception("mbedtls_pk_sign failed, err=" + openvpn::to_string(status));

	        if(sig.size() != sig_size)
	            throw Exception("unexpected signature size");

            // encode base64 signature

            signreq.sig = base64->encode(sig);

            OPENVPN_LOG("SIGNATURE[" << sig_size << "]: " << signreq.sig);
	    }
	    catch(const std::exception& e)
	    {
            signreq.error = true;
            signreq.errorText = std::string("external_pki_sign_request: ") + e.what();
	    }
    }
    else

#endif

    {
        signreq.error = true;
        signreq.errorText = "external_pki_sign_request not implemented";
    }
}

int Client::rng_callback(void *arg, unsigned char *data, size_t len)
{
    Client *self = (Client *)arg;

    if(!self->rng)
    {
        self->rng.reset(new SSLLib::RandomAPI(false));
        self->rng->assert_crypto();
    }

    return self->rng->rand_bytes_noexcept(data, len) ? 0 : -1; // using -1 as a general-purpose mbed TLS error code
}

bool Client::pause_on_connection_timeout()
{
    return false;
}

#ifdef OPENVPN_REMOTE_OVERRIDE

bool Client::remote_override_enabled()
{
    return !remote_override_cmd.empty();
}

void Client::remote_override(ClientAPI::RemoteOverride& ro)
{
    RedirectPipe::InOut pio;
    Argv argv;
    argv.emplace_back(remote_override_cmd);
    OPENVPN_LOG(argv.to_string());

    const int status = system_cmd(remote_override_cmd, argv, nullptr, pio, RedirectPipe::IGNORE_ERR);

    if(!status)
    {
	    const std::string out = string::first_line(pio.out);

        OPENVPN_LOG("REMOTE OVERRIDE: " << out);

        auto svec = string::split(out, ',');

        if(svec.size() == 4)
	    {
            ro.host = svec[0];
            ro.ip = svec[1];
            ro.port = svec[2];
            ro.proto = svec[3];
	    }
	    else
	        ro.error = "cannot parse remote-override, expecting host,ip,port,proto (at least one or both of host and ip must be defined)";
    }
    else
        ro.error = "status=" + std::to_string(status);
}

#endif

// C functions

static Client *the_client = nullptr;

void show_intro(void)
{
    std::cout << HUMMINGBIRD_FULL_NAME << " - " << HUMMINGBIRD_RELEASE_DATE << std::endl << std::endl;
}

bool check_if_root()
{
    uid_t uid, euid;
    bool retval = false;

    uid=getuid();
    euid=geteuid();

    if(uid != 0 || uid != euid)
        retval = false;
    else
        retval = true;

    return retval;
}

bool init_check(void)
{
    DIR* resdir;
    FILE *flock;
    char buf[256];
    NetFilter *netFilter = new NetFilter(RESOURCE_DIRECTORY);
    bool dirtyExit = false, lockFileFound = false;

    // Check for resource directory

    resdir = opendir(RESOURCE_DIRECTORY);

    if(resdir)
    {
        closedir(resdir);
    }
    else if(errno == ENOENT)
    {
        std::cout << "Creating resource directory " << RESOURCE_DIRECTORY << std::endl;

        if(mkdir(RESOURCE_DIRECTORY, 0755) != 0)
        {
            std::cout << "Cannot create " << RESOURCE_DIRECTORY << " (Error " << errno << " - " << strerror(errno) << std::endl;

            return false;
        }
    }
    else
    {
        std::cout << "Cannot access resource directory" << RESOURCE_DIRECTORY << std::endl;

        return false;
    }

    if(netFilter->backupFileExists(NetFilter::IP::v4) || netFilter->backupFileExists(NetFilter::IP::v6))
        dirtyExit = true;

    delete netFilter;

#if defined(OPENVPN_PLATFORM_LINUX)

    DNSManager *dnsManager = new DNSManager(RESOLVDOTCONF_BACKUP);

    if(dnsManager->resolvDotConfBackupExists())
        dirtyExit = true;

    delete dnsManager;

#endif

    if(access(HUMMINGBIRD_LOCK_FILE, F_OK) == 0)
        lockFileFound = true;

    if(lockFileFound == true || dirtyExit == true)
    {
        if(lockFileFound == true)
        {
            std::cout << "This program is already running ";

            flock = fopen(HUMMINGBIRD_LOCK_FILE, "r");

            if(fgets(buf, sizeof(buf), flock) != NULL)
                std::cout << "(PID " << atoi(buf) << ") ";

            std::cout << "or it did not gracefully" << std::endl;

            fclose(flock);

            std::cout << "exit in its previous execution. In case you have restarted this computer" << std::endl;
            std::cout << "or just powered it on, you can remove the lock file " << HUMMINGBIRD_LOCK_FILE << std::endl;
            std::cout << "and start this program again." << std::endl;
            std::cout << "In case you are sure this program is not already running and your network" << std::endl;
            std::cout << "connection is not working as expected, you can run this program with the" << std::endl;
            std::cout << "\"--recover-network\" option in order to try restoring your system network" << std::endl;
            std::cout << "settings." << std::endl;
        }
        else
        {
            std::cout << "It seems this program did not exit gracefully or has been killed." << std::endl;
            std::cout << "Your system may not be working properly and your network connection may not work" << std::endl;
            std::cout << "as expected. To recover your network settings, run this program again and use" << std::endl;
            std::cout << "the \"--recover-network\" option." << std::endl;
        }

        std::cout << std::endl;

        return false;
    }

    // Create lock file

    flock = fopen(HUMMINGBIRD_LOCK_FILE, "w");

    fprintf(flock, "%d\n", getpid());

    fclose(flock);

    return true;
}

bool clean_up(void)
{
    // remove lock file

    if(access(HUMMINGBIRD_LOCK_FILE, F_OK) != -1)
        unlink(HUMMINGBIRD_LOCK_FILE);

    // remove system dns backup file

    if(access(SYSTEM_DNS_BACKUP_FILE, F_OK) != -1)
        unlink(SYSTEM_DNS_BACKUP_FILE);

    return true;
}

static void worker_thread()
{
    try
    {
        std::cout << date_time() << " Starting thread" << std::endl;

        ClientAPI::Status connect_status = the_client->connect();

        if(connect_status.error)
        {
	        std::cout << date_time() << " OpenVPN3 CONNECT ERROR: ";

            if(!connect_status.status.empty())
	            std::cout << connect_status.status << ": ";

            std::cout << connect_status.message << std::endl;
        }
    }
    catch(const std::exception& e)
    {
        std::cout << date_time() << " OpenVPN3 Connect thread exception: " << e.what() << std::endl;
    }

    std::cout << date_time() << " Thread finished" << std::endl;
}

static std::string read_profile(const char *fn, const std::string* profile_content)
{
    if(!string::strcasecmp(fn, "http") && profile_content && !profile_content->empty())
        return *profile_content;
    else
    {
        if(access(fn, F_OK) == -1)
	        OPENVPN_THROW_EXCEPTION("Profile " << fn << " not found");

        ProfileMerge pm(fn, "ovpn", "", ProfileMerge::FOLLOW_FULL, ProfileParseLimits::MAX_LINE_SIZE, ProfileParseLimits::MAX_PROFILE_SIZE);

        if(pm.status() != ProfileMerge::MERGE_SUCCESS)
	        OPENVPN_THROW_EXCEPTION("merge config error: " << pm.status_string() << " : " << pm.error());

        return pm.profile_content();
    }
}

static void signal_handler(int signum)
{
    switch(signum)
    {
        case SIGTERM:
        case SIGINT:
        case SIGPIPE:
        {
            std::cout << "received stop signal " << signum << std::endl;

            if(the_client)
	            the_client->stop();
        }
        break;

        case SIGHUP:
        {
            std::cout << "received reconnect signal " << signum << std::endl;

            if(the_client)
	            the_client->reconnect(0);
        }
        break;

        case SIGUSR1:
        {
            if(the_client)
	            the_client->print_stats();
        }
        break;

        case SIGUSR2:
        {
	        // toggle pause/resume

            static bool hup = false;

            std::cout << "received pause/resume toggle signal " << signum << std::endl;

            if(the_client)
	        {
	            if(hup)
	                the_client->resume();
	            else
	                the_client->pause("pause-resume-signal");

                hup = !hup;
	        }
        }
        break;

        default:
        {
            std::cout << "received unhandled signal " << signum << std::endl;
        }
        break;
    }
}

static void start_thread(Client& client)
{
    std::unique_ptr<std::thread> thread;

    // start connect thread

    the_client = &client;

    thread.reset(new std::thread([]()
        {
	        worker_thread();
        }));

    {
        // catch signals that might occur while we're in join()

        Signal signal(signal_handler, Signal::F_SIGINT|Signal::F_SIGTERM|Signal::F_SIGPIPE|Signal::F_SIGHUP|Signal::F_SIGUSR1|Signal::F_SIGUSR2);

        // wait for connect thread to exit

        thread->join();
    }

    the_client = nullptr;
}

int openvpn_client(int argc, char *argv[], const std::string* profile_content)
{
    static const struct option longopts[] =
    {
        { "username",           required_argument,  nullptr,      'u' },
        { "password",           required_argument,  nullptr,      'p' },
        { "response",           required_argument,  nullptr,      'r' },
        { "dc",                 required_argument,  nullptr,      'D' },
        { "proto",              required_argument,  nullptr,      'P' },
        { "ipv6",               required_argument,  nullptr,      '6' },
        { "server",             required_argument,  nullptr,      's' },
        { "port",               required_argument,  nullptr,      'R' },
        { "cipher",             required_argument,  nullptr,      'C' },
        { "ncp-disable",        no_argument,        nullptr,      'n' },
        { "ignore-dns-push",    no_argument,        nullptr,      'i' },
        { "network-lock",       required_argument,  nullptr,      'N' },
        { "gui-version",        required_argument,  nullptr,      'E' },
        { "timeout",            required_argument,  nullptr,      't' },
        { "compress",           required_argument,  nullptr,      'c' },
        { "pk-password",        required_argument,  nullptr,      'z' },
        { "tvm-override",       required_argument,  nullptr,      'M' },
        { "proxy-host",         required_argument,  nullptr,      'y' },
        { "proxy-port",         required_argument,  nullptr,      'q' },
        { "proxy-username",     required_argument,  nullptr,      'U' },
        { "proxy-password",     required_argument,  nullptr,      'W' },
        { "peer-info",          required_argument,  nullptr,      'I' },
        { "gremlin",            required_argument,  nullptr,      'G' },
        { "proxy-basic",        no_argument,        nullptr,      'B' },
        { "alt-proxy",          no_argument,        nullptr,      'A' },
        { "dco",                no_argument,        nullptr,      'd' },
        { "eval",               no_argument,        nullptr,      'e' },
        { "self-test",          no_argument,        nullptr,      'T' },
        { "cache-password",     no_argument,        nullptr,      'H' },
        { "no-cert",            no_argument,        nullptr,      'x' },
        { "force-aes-cbc",      no_argument,        nullptr,      'f' },
        { "google-dns",         no_argument,        nullptr,      'g' },
        { "persist-tun",        no_argument,        nullptr,      'j' },
        { "def-keydir",         required_argument,  nullptr,      'k' },
        { "merge",              no_argument,        nullptr,      'm' },
        { "version",            no_argument,        nullptr,      'v' },
        { "help",               no_argument,        nullptr,      'h' },
        { "auto-sess",          no_argument,        nullptr,      'a' },
        { "auth-retry",         no_argument,        nullptr,      'Y' },
        { "tcprof-override",    required_argument,  nullptr,      'X' },
        { "ssl-debug",          required_argument,  nullptr,       1  },
        { "epki-cert",          required_argument,  nullptr,       2  },
        { "epki-ca",            required_argument,  nullptr,       3  },
        { "epki-key",           required_argument,  nullptr,       4  },

#ifdef OPENVPN_REMOTE_OVERRIDE
        { "remote-override",    required_argument,  nullptr,       5  },
#endif

        { "recover-network",    no_argument,        nullptr,       6  },
        { nullptr,              0,                  nullptr,       0  }
    };

    int ret = 0;
    char *exec_name = argv[0];

    auto cleanup = Cleanup([]()
        {
            the_client = nullptr;
        });

    try
    {
        if(argc >= 2)
        {
            std::string username;
            std::string password;
            std::string response;
            std::string dynamicChallengeCookie;
            std::string proto;
            std::string ipv6;
            std::string server;
            std::string port;
            std::string cipher_alg = "";
            std::string gui_version = HUMMINGBIRD_FULL_NAME;
            int timeout = 0;
            std::string compress;
            std::string privateKeyPassword;
            std::string tlsVersionMinOverride;
            std::string tlsCertProfileOverride;
            std::string proxyHost;
            std::string proxyPort;
            std::string proxyUsername;
            std::string proxyPassword;
            std::string peer_info;
            std::string gremlin;
            bool eval = false;
            bool ncp_disable = false;
            bool network_lock = true;
            bool ignore_dns_push = false;
            bool self_test = false;
            bool cachePassword = false;
            bool disableClientCert = false;
            bool proxyAllowCleartextAuth = false;
            int defaultKeyDirection = -1;
            bool forceAesCbcCiphersuites = false;
            int sslDebugLevel = 0;
            bool googleDnsFallback = false;
            bool autologinSessions = false;
            bool retryOnAuthFailed = false;
            bool tunPersist = false;
            bool merge = false;
            bool version = false;
            bool altProxy = false;
            bool dco = false;
            std::string epki_cert_fn;
            std::string epki_ca_fn;
            std::string epki_key_fn;

#ifdef OPENVPN_REMOTE_OVERRIDE
	        std::string remote_override_cmd;
#endif

	        int ch;

            optind = 1;

            while((ch = getopt_long(argc, argv, "BAdeTniHxfgjmvhaYu:p:r:D:P:6:s:t:c:z:M:y:q:U:W:I:G:k:X:R:C:N:E:", longopts, nullptr)) != -1)
	        {
	            switch(ch)
	            {
	                case 'h':
                    {
                        throw usage();
                    }
		            break;

	                case 1: // ssl-debug
                    {
		                sslDebugLevel = ::atoi(optarg);
                    }
		            break;

	                case 2: // --epki-cert
                    {
		                epki_cert_fn = optarg;
                    }
		            break;

                    case 3: // --epki-ca
                    {
		                epki_ca_fn = optarg;
                    }
		            break;

                    case 4: // --epki-key
                    {
		                epki_key_fn = optarg;
                    }
		            break;

#ifdef OPENVPN_REMOTE_OVERRIDE
	                case 5: // --remote-override
                    {
		                remote_override_cmd = optarg;
                    }
		            break;
#endif

                    case 6: // --recover-network
                    {
                        std::cout << "ERROR: --recover-network option must be used alone" << std::endl << std::endl;

                        return 1;
                    }
		            break;

	                case 'e':
                    {
		                eval = true;
                    }
		            break;

	                case 'C':
                    {
		                cipher_alg = optarg;
                    }
		            break;

	                case 'n':
                    {
		                ncp_disable = true;
                    }
		            break;

	                case 'N':
                    {
		                if(strcmp(optarg, "on") != 0 && strcmp(optarg, "off") != 0)
                        {
                            std::cout << "ERROR: --network-lock option must be on or off" << std::endl << std::endl;

                            return 1;
                        }

                        if(strcmp(optarg, "on") == 0)
                            network_lock = true;
                        else
                            network_lock = false;
                    }
		            break;

	                case 'E':
                    {
		                if(strcmp(optarg, "") == 0)
                        {
                            std::cout << "ERROR: invalid gui version" << std::endl << std::endl;

                            return 1;
                        }

                        gui_version = optarg;
                    }
		            break;

	                case 'i':
                    {
		                ignore_dns_push = true;
                    }
		            break;

	                case 'T':
                    {
		                self_test = true;
                    }
		            break;

	                case 'H':
                    {
		                cachePassword = true;
                    }
		            break;

	                case 'x':
                    {
		                disableClientCert = true;
                    }
		            break;

	                case 'u':
                    {
		                username = optarg;
                    }
		            break;

	                case 'p':
                    {
		                password = optarg;
                    }
		            break;

	                case 'r':
                    {
		                response = optarg;
                    }
		            break;

	                case 'P':
                    {
		                proto = optarg;
                    }
		            break;

	                case '6':
                    {
		                ipv6 = optarg;
                    }
		            break;

	                case 's':
                    {
		                server = optarg;
                    }
		            break;

	                case 'R':
                    {
		                port = optarg;
                    }
		            break;

	                case 't':
                    {
		                timeout = ::atoi(optarg);
                    }
		            break;

	                case 'c':
                    {
		                compress = optarg;
                    }
		            break;

	                case 'z':
                    {
		                privateKeyPassword = optarg;
                    }
		            break;

	                case 'M':
                    {
		                tlsVersionMinOverride = optarg;
                    }
		            break;

	                case 'X':
                    {
		                tlsCertProfileOverride = optarg;
                    }
		            break;

	                case 'y':
                    {
		                proxyHost = optarg;
                    }
		            break;

	                case 'q':
                    {
		                proxyPort = optarg;
                    }
		            break;

	                case 'U':
                    {
		                proxyUsername = optarg;
                    }
		            break;

	                case 'W':
                    {
		                proxyPassword = optarg;
                    }
		            break;

	                case 'B':
                    {
		                proxyAllowCleartextAuth = true;
                    }
		            break;

	                case 'A':
                    {
		                altProxy = true;
                    }
		            break;

	                case 'd':
                    {
		                dco = true;
                    }
		            break;

	                case 'f':
                    {
		                forceAesCbcCiphersuites = true;
                    }
		            break;

	                case 'g':
                    {
		                googleDnsFallback = true;
                    }
		            break;

	                case 'a':
                    {
		                autologinSessions = true;
                    }
		            break;

	                case 'Y':
                    {
		                retryOnAuthFailed = true;
                    }
		            break;

	                case 'j':
                    {
		                tunPersist = true;
                    }
		            break;

	                case 'm':
                    {
		                merge = true;
                    }
		            break;

	                case 'v':
                    {
		                version = true;
                    }
		            break;

	                case 'k':
		            {
		                const std::string arg = optarg;

                        if(arg == "bi" || arg == "bidirectional")
		                    defaultKeyDirection = -1;
		                else if(arg == "0")
		                    defaultKeyDirection = 0;
		                else if(arg == "1")
		                    defaultKeyDirection = 1;
		                else
		                    OPENVPN_THROW_EXCEPTION("bad default key-direction: " << arg);
		            }
		            break;

	                case 'D':
                    {
		                dynamicChallengeCookie = optarg;
                    }
		            break;

	                case 'I':
                    {
		                peer_info = optarg;
                    }
		            break;

                    case 'G':
                    {
		                gremlin = optarg;
                    }
		            break;

	                default:
                    {
		                throw usage();
	                }
                    break;
                }
	        }

            argc -= optind;
	        argv += optind;

	        if(version)
	        {
                std::cout << ClientAPI::OpenVPNClient::platform() << std::endl;
                std::cout << ClientAPI::OpenVPNClient::copyright() << std::endl << std::endl;
                std::cout << "Released under the GNU General Public License version 3 (GPLv3)" << std::endl << std::endl;

                aboutDevelopmentCredits();
	        }
	        else if(self_test)
            {
                std::cout << ClientAPI::OpenVPNClient::crypto_self_test();
            }
	        else if(merge)
	        {
	            if(argc != 1)
	                throw usage();

	            std::cout << read_profile(argv[0], profile_content);
	        }
	        else
	        {
	            if(argc < 1)
	                throw usage();

	            bool retry;

	            do
                {
	                retry = false;

                    ClientAPI::Config config;
                    config.guiVersion = gui_version;

                    config.content = read_profile(argv[0], profile_content);

	                for(int i = 1; i < argc; ++i)
		            {
                        config.content += argv[i];
                        config.content += '\n';
		            }

                    config.serverOverride = server;
                    config.portOverride = port;
                    config.protoOverride = proto;
                    config.cipherOverride = cipher_alg;
                    config.connTimeout = timeout;
                    config.compressionMode = compress;
                    config.ipv6 = ipv6;
                    config.disableNCP = ncp_disable;
                    config.privateKeyPassword = privateKeyPassword;
                    config.tlsVersionMinOverride = tlsVersionMinOverride;
                    config.tlsCertProfileOverride = tlsCertProfileOverride;
                    config.disableClientCert = disableClientCert;
                    config.proxyHost = proxyHost;
                    config.proxyPort = proxyPort;
                    config.proxyUsername = proxyUsername;
                    config.proxyPassword = proxyPassword;
                    config.proxyAllowCleartextAuth = proxyAllowCleartextAuth;
                    config.altProxy = altProxy;
                    config.dco = dco;
                    config.defaultKeyDirection = defaultKeyDirection;
                    config.forceAesCbcCiphersuites = forceAesCbcCiphersuites;
                    config.sslDebugLevel = sslDebugLevel;
                    config.googleDnsFallback = googleDnsFallback;
                    config.autologinSessions = autologinSessions;
                    config.retryOnAuthFailed = retryOnAuthFailed;
                    config.tunPersist = tunPersist;
                    config.gremlinConfig = gremlin;
                    config.info = true;
                    config.wintun = false;

	                if(!epki_cert_fn.empty())
		                config.externalPkiAlias = "epki"; // dummy string

	                PeerInfo::Set::parse_csv(peer_info, config.peerInfo);

                    // allow -s server override to reference a friendly name
                    // in the config.
                    //   setenv SERVER <HOST>/<FRIENDLY_NAME>

                    if(!config.serverOverride.empty())
		            {
		                const ClientAPI::EvalConfig eval = ClientAPI::OpenVPNClient::eval_config_static(config);

                        for(auto &se : eval.serverList)
                        {
		                    if(config.serverOverride == se.friendlyName)
			                {
			                    config.serverOverride = se.server;

                                break;
			                }
		                }
		            }

	                if(eval)
		            {
		                const ClientAPI::EvalConfig eval = ClientAPI::OpenVPNClient::eval_config_static(config);

                        std::cout << "EVAL PROFILE" << std::endl;
                        std::cout << "error=" << eval.error << std::endl;
                        std::cout << "message=" << eval.message << std::endl;
                        std::cout << "userlockedUsername=" << eval.userlockedUsername << std::endl;
                        std::cout << "profileName=" << eval.profileName << std::endl;
                        std::cout << "friendlyName=" << eval.friendlyName << std::endl;
                        std::cout << "autologin=" << eval.autologin << std::endl;
                        std::cout << "externalPki=" << eval.externalPki << std::endl;
                        std::cout << "staticChallenge=" << eval.staticChallenge << std::endl;
                        std::cout << "staticChallengeEcho=" << eval.staticChallengeEcho << std::endl;
                        std::cout << "privateKeyPasswordRequired=" << eval.privateKeyPasswordRequired << std::endl;
                        std::cout << "allowPasswordSave=" << eval.allowPasswordSave << std::endl;

		                if(!config.serverOverride.empty())
		                    std::cout << "server=" << config.serverOverride << std::endl;

		                for(size_t i = 0; i < eval.serverList.size(); ++i)
		                {
		                    const ClientAPI::ServerEntry& se = eval.serverList[i];

                            std::cout << "Server[" << i << "] " << se.server << "/" << se.friendlyName << std::endl;
		                }

		                for(size_t i = 0; i < eval.remoteList.size(); ++i)
		                {
		                    const ClientAPI::RemoteEntry& re = eval.remoteList[i];

                            std::cout << "Remote[" << i << "] " << re.server << " Port: " << re.port << " Protocol: " << re.protocol << std::endl;
		                }
		            }
	                else
		            {
		                Client client;

                        const ClientAPI::EvalConfig eval = client.eval_config(config);

                        if(eval.error)
		                    OPENVPN_THROW_EXCEPTION("eval config error: " << eval.message);

		                if(eval.autologin)
		                {
		                    if(!username.empty() || !password.empty())
			                    std::cout << "NOTE: creds were not needed" << std::endl;
		                }
		                else
		                {
		                    if(username.empty())
			                    OPENVPN_THROW_EXCEPTION("need creds");

                            ClientAPI::ProvideCreds creds;

                            if(password.empty() && dynamicChallengeCookie.empty())
			                    password = get_password("Password:");

                            creds.username = username;
                            creds.password = password;
                            creds.response = response;
                            creds.dynamicChallengeCookie = dynamicChallengeCookie;
                            creds.replacePasswordWithSessionID = true;
                            creds.cachePassword = cachePassword;

                            ClientAPI::Status creds_status = client.provide_creds(creds);

                            if(creds_status.error)
			                    OPENVPN_THROW_EXCEPTION("creds error: " << creds_status.message);
		                }

		                // external PKI

		                if(!epki_cert_fn.empty())
		                {
		                    client.epki_cert = read_text_utf8(epki_cert_fn);

                            if(!epki_ca_fn.empty())
			                    client.epki_ca = read_text_utf8(epki_ca_fn);

#if defined(USE_MBEDTLS)

                            if(!epki_key_fn.empty())
                            {
                                const std::string epki_key_txt = read_text_utf8(epki_key_fn);

                                client.epki_ctx.parse(epki_key_txt, "EPKI", privateKeyPassword);
                            }
		                    else
			                    OPENVPN_THROW_EXCEPTION("--epki-key must be specified");

#endif
		                }

#ifdef OPENVPN_REMOTE_OVERRIDE
                        client.set_remote_override_cmd(remote_override_cmd);
#endif

		                // start the client thread

                        client.setConfig(config);
                        client.setEvalConfig(eval);

                        client.enableNetworkLock(network_lock);

                        client.ignoreDnsPush(ignore_dns_push);

                        start_thread(client);

		                // Get dynamic challenge response

                        if(client.is_dynamic_challenge())
		                {
                            std::cout << "ENTER RESPONSE" << std::endl;

                            std::getline(std::cin, response);

		                    if(!response.empty())
			                {
                                dynamicChallengeCookie = client.dynamic_challenge_cookie();

                                retry = true;
			                }
		                }
		                else
		                {
		                    // print closing stats

		                    client.print_stats();
		                }
		            }
	            } while (retry);
	        }
        }
        else
            throw usage();
    }
    catch(const usage&)
    {
        std::cout << "usage: " << exec_name << " [options] <config-file> [extra-config-directives...]" << std::endl;
        std::cout << "--help, -h            : show this help page" << std::endl;
        std::cout << "--version, -v         : show version info" << std::endl;
        std::cout << "--eval, -e            : evaluate profile only (standalone)" << std::endl;
        std::cout << "--merge, -m           : merge profile into unified format (standalone)" << std::endl;
        std::cout << "--username, -u        : username" << std::endl;
        std::cout << "--password, -p        : password" << std::endl;
        std::cout << "--response, -r        : static response" << std::endl;
        std::cout << "--dc, -D              : dynamic challenge/response cookie" << std::endl;
        std::cout << "--cipher, -C          : encrypt packets with specific cipher algorithm (alg)" << std::endl;
        std::cout << "--proto, -P           : protocol override (udp|tcp)" << std::endl;
        std::cout << "--server, -s          : server override" << std::endl;
        std::cout << "--port, -R            : port override" << std::endl;
        std::cout << "--ncp-disable, -n     : disable negotiable crypto parameters" << std::endl;
        std::cout << "--network-lock, -N    : enable/disable network filter and lock (on|off, default on)" << std::endl;
        std::cout << "--gui-version, -E     : set custom gui version (text)" << std::endl;
        std::cout << "--ignore-dns-push, -i : ignore DNS push request and use system DNS settings" << std::endl;

#ifdef OPENVPN_REMOTE_OVERRIDE
        std::cout << "--remote-override     : command to run to generate next remote (returning host,ip,port,proto)" << std::endl;
#endif

        std::cout << "--ipv6, -6            : combined IPv4/IPv6 tunnel (yes|no|default)" << std::endl;
        std::cout << "--timeout, -t         : timeout" << std::endl;
        std::cout << "--compress, -c        : compression mode (yes|no|asym)" << std::endl;
        std::cout << "--pk-password, -z     : private key password" << std::endl;
        std::cout << "--tvm-override, -M    : tls-version-min override (disabled, default, tls_1_x)" << std::endl;
        std::cout << "--tcprof-override, -X : tls-cert-profile override (" <<

#ifdef OPENVPN_USE_TLS_MD5
            "insecure, " <<
#endif
            "legacy, preferred, etc.)" << std::endl;

        std::cout << "--proxy-host, -y      : HTTP proxy hostname/IP" << std::endl;
        std::cout << "--proxy-port, -q      : HTTP proxy port" << std::endl;
        std::cout << "--proxy-username, -U  : HTTP proxy username" << std::endl;
        std::cout << "--proxy-password, -W  : HTTP proxy password" << std::endl;
        std::cout << "--proxy-basic, -B     : allow HTTP basic auth" << std::endl;
        std::cout << "--alt-proxy, -A       : enable alternative proxy module" << std::endl;
        std::cout << "--dco, -d             : enable data channel offload" << std::endl;
        std::cout << "--cache-password, -H  : cache password" << std::endl;
        std::cout << "--no-cert, -x         : disable client certificate" << std::endl;
        std::cout << "--def-keydir, -k      : default key direction ('bi', '0', or '1')" << std::endl;
        std::cout << "--force-aes-cbc, -f   : force AES-CBC ciphersuites" << std::endl;
        std::cout << "--ssl-debug           : SSL debug level" << std::endl;
        std::cout << "--google-dns, -g      : enable Google DNS fallback" << std::endl;
        std::cout << "--auto-sess, -a       : request autologin session" << std::endl;
        std::cout << "--auth-retry, -Y      : retry connection on auth failure" << std::endl;
        std::cout << "--persist-tun, -j     : keep TUN interface open across reconnects" << std::endl;
        std::cout << "--peer-info, -I       : peer info key/value list in the form K1=V1,K2=V2,..." << std::endl;
        std::cout << "--gremlin, -G         : gremlin info (send_delay_ms, recv_delay_ms, send_drop_prob, recv_drop_prob)" << std::endl;
        std::cout << "--epki-ca             : simulate external PKI cert supporting intermediate/root certs" << std::endl;
        std::cout << "--epki-cert           : simulate external PKI cert" << std::endl;
        std::cout << "--epki-key            : simulate external PKI private key" << std::endl;
        std::cout << "--recover-network     : recover network settings after a crash or unexpected exit" << std::endl << std::endl;

        aboutDevelopmentCredits();

        ret = 2;
    }

    return ret;
}

#if defined(OPENVPN_PLATFORM_LINUX)

bool load_linux_module(const char *module_name, const char *module_params, bool stdOutput)
{
    std::ostringstream os;
    int retval;
    bool result = false;

    retval = load_kernel_module(module_name, module_params);

    os.str("");

    switch(retval)
    {
        case MODULE_LOAD_SUCCESS:
        {
            os << "Successfully loaded kernel module " << module_name;

            result = true;
        }
        break;

        case MODULE_ALREADY_LOADED:
        {
            result = true;
        }
        break;

        case MODULE_NOT_FOUND:
        {
            os << "WARNING: Kernel module " << module_name << " not found. (" << retval << ")";

            result = true;
        }
        break;

        default:
        {
            os << "ERROR: Error while loading kernel module " << module_name << " (" << retval << ")";

            result = true;
        }
        break;
    }

    if(os.str() != "")
    {
        os << std::endl;

        if(stdOutput == false)
            OPENVPN_LOG_STRING(os.str());
        else
            std::cout << os.str();
    }

    return result;
}

#endif

void aboutDevelopmentCredits(void)
{
    std::cout << "Open Source Project by AirVPN (https://airvpn.org)" << std::endl << std::endl;
    std::cout << "Linux and macOS design, development and coding: ProMIND" << std::endl << std::endl;

    std::cout << "Special thanks to the AirVPN community for the valuable help," << std::endl;
    std::cout << "support, suggestions and testing." << std::endl << std::endl;
}

int main(int argc, char *argv[])
{
    int retval = 0;

#ifdef OPENVPN_LOG_LOGBASE_H

    LogBaseSimple log;

#endif

    show_intro();

    if(check_if_root() == false)
    {
        std::cout << "You need to be root in order to run this program." << std::endl << std::endl;

        return 1;
    }

    if(argc == 2)
    {
        if(strcmp(argv[1], "--recover-network") == 0)
        {
            if(access(HUMMINGBIRD_LOCK_FILE, F_OK) != 0)
            {
                std::cout << "It seems this program has properly exited in its last run and" << std::endl;
                std::cout << "it has already restored network settings on exit." << std::endl << std::endl;
            }

            Client *client = new Client();

            client->restoreNetworkSettings(true);

            delete client;

            std::cout << std::endl;

            clean_up();

            return 0;
        }
    }

    if(init_check() == false)
        return 1;

    try
    {
        Client::init_process();

        retval = openvpn_client(argc, argv, nullptr);
    }
    catch(const std::exception& e)
    {
        std::cout << "Error: " << e.what() << std::endl;

        retval = 1;
    }

    Client::uninit_process();

    if(!clean_up())
        retval = 1;

    return retval;
}


