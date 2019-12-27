/*
 * netfilter.hpp
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

#ifndef NETFILTER_CLASS_HPP
#define NETFILTER_CLASS_HPP

#include <string>
#include <vector>

class NetFilter
{
    public:

    enum class Mode
    {
        AUTO,
        IPTABLES,
        PF,
        NFTABLES,
        UNKNOWN
    };

    enum class Protocol
    {
        UDP,
        TCP,
        ANY
    };

    enum class IP
    {
        v4,
        v6,
        ANY
    };

    enum class Direction
    {
        INPUT,
        OUTPUT
    };

    NetFilter(std::string workdir, Mode mode = Mode::AUTO);
    ~NetFilter();

    bool backupFileExists(IP ip);
    bool init();
    bool restore();
    void setup(std::string loopbackIface);
    bool commitRules();
    bool addAllowRule(IP ip, Direction direction, std::string interface, Protocol protocol, std::string sourceIP, int sourcePort, std::string destinationIP, int destinationPort);
    bool addRejectRule(IP ip, Direction direction, std::string interface, Protocol protocol, std::string sourceIP, int sourcePort, std::string destinationIP, int destinationPort);
    bool commitAllowRule(IP ip, Direction direction, std::string interface, Protocol protocol, std::string sourceIP, int sourcePort, std::string destinationIP, int destinationPort);
    bool commitRejectRule(IP ip, Direction direction, std::string interface, Protocol protocol, std::string sourceIP, int sourcePort, std::string destinationIP, int destinationPort);
    bool commitRemoveAllowRule(IP ip, Direction direction, std::string interface, Protocol protocol, std::string sourceIP, int sourcePort, std::string destinationIP, int destinationPort);
    bool commitRemoveRejectRule(IP ip, Direction direction, std::string interface, Protocol protocol, std::string sourceIP, int sourcePort, std::string destinationIP, int destinationPort);
    Mode getMode();
    std::string getModeDescription();
    bool setMode(Mode mode);
    bool addIgnoredInterface(std::string interface);
    void clearIgnoredInterfaces();
    bool isFirewalldRunning();
    bool isUfwRunning();
    bool isIPTablesLegacy();

    private:

    const char *systemctlBinary = "systemctl";

    bool checkSystemctlService(std::string name);
    bool readFile(std::string fname, char *buffer, int size);

    // iptables

    const char *iptablesBinary = NULL;
    const char *iptablesSaveBinary = NULL;
    const char *iptablesRestoreBinary = NULL;
    const char *iptablesCurrentBinary = "iptables";
    const char *iptablesCurrentSaveBinary = "iptables-save";
    const char *iptablesCurrentRestoreBinary = "iptables-restore";
    const char *iptablesLegacyBinary = "iptables-legacy";
    const char *iptablesLegacySaveBinary = "iptables-legacy-save";
    const char *iptablesLegacyRestoreBinary = "iptables-legacy-restore";
    const char *ip6tablesBinary = NULL;
    const char *ip6tablesSaveBinary = NULL;
    const char *ip6tablesRestoreBinary = NULL;
    const char *ip6tablesCurrentBinary = "ip6tables";
    const char *ip6tablesCurrentSaveBinary = "ip6tables-save";
    const char *ip6tablesCurrentRestoreBinary = "ip6tables-restore";
    const char *ip6tablesLegacyBinary = "ip6tables-legacy";
    const char *ip6tablesLegacySaveBinary = "ip6tables-legacy-save";
    const char *ip6tablesLegacyRestoreBinary = "ip6tables-legacy-restore";

    bool iptablesSave(IP ip);
    bool iptablesRestore(IP ip);
    bool iptablesFlush(IP ip);
    void iptablesSetup(std::string loopbackIface);
    void iptablesResetRules(IP ip);
    std::string createIptablesGenericRule(Direction direction, std::string interface, Protocol protocol, std::string sourceIP, int sourcePort, std::string destinationIP, int destinationPort);
    void iptablesAddRule(IP ip, std::string rule);
    bool iptablesCommitRule(IP ip, std::string rule);
    bool iptablesCommit(IP ip);

    std::string iptablesSaveFile = "iptables-save.txt";
    std::string ip6tablesSaveFile = "ip6tables-save.txt";
    std::string iptablesRules = "";
    std::string ip6tablesRules = "";

    // nftables

    const char *nftBinary = "nft";

    bool nftablesSave();
    bool nftablesRestore();
    bool nftablesFlush();
    void nftablesSetup(std::string loopbackIface);
    void nftablesResetRules();
    std::string createNftablesGenericRule(IP ip, Direction direction, std::string interface, Protocol protocol, std::string sourceIP, int sourcePort, std::string destinationIP, int destinationPort);
    void nftablesAddRule(std::string rule);
    bool nftablesCommitRule(std::string rule);
    bool nftablesCommit();

    std::string nftablesSaveFile = "nftables-save.txt";
    std::string nftablesRules = "";

    // pf

    const char *pfctlBinary = "pfctl";

    bool pfEnable();
    bool pfSave();
    bool pfRestore();
    bool pfFlush();
    void pfSetup(std::string loopbackIface);
    void pfResetRules();
    std::string createPfGenericRule(IP ip, Direction direction, std::string interface, Protocol protocol, std::string sourceIP, int sourcePort, std::string destinationIP, int destinationPort);
    void pfAddRule(std::string rule);
    bool pfCommit();
    bool pfAddIgnoredInterface(std::string interface);

    std::string pfSaveFile = "pf-save.txt";
    std::string pfNetFilterRulesFile = "pf-netfilter-rules.txt";
    std::string pfConfFile = "/etc/pf.conf";
    std::string pfRules = "";

   
    char binpath[128];

    char *charBuffer = NULL;

    const int charBufferSize = 65536;

    Mode filterMode = Mode::UNKNOWN;
    std::string workingDirectory = "";
    std::string loopbackInterface = "";
    std::vector<std::string> ignoredInterface;

    bool firewalldAvailable = false;
    bool ufwAvailable = false;
    bool iptablesAvailable = false;
    bool iptablesLegacy = false;
    bool nftablesAvailable = false;
    bool pfAvailable = false;
};

#endif
