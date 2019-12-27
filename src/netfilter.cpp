/*
 * netfilter.cpp
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

#include "include/netfilter.hpp"
#include "include/execproc.h"
#include <fstream>
#include <sstream>
#include <cstring>
#include <iterator>
#include <vector>
#include <algorithm>
#include <regex>
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>

NetFilter::NetFilter(std::string workdir, Mode mode)
{
    workingDirectory = workdir;

    firewalldAvailable = false;
    ufwAvailable = false;
    iptablesAvailable = false;
    iptablesLegacy = false;
    nftablesAvailable = false;
    pfAvailable = false;

    loopbackInterface = "";

    clearIgnoredInterfaces();

    filterMode = Mode::UNKNOWN;

    charBuffer = (char *)malloc(charBufferSize);

    firewalldAvailable = checkSystemctlService("firewalld");

    ufwAvailable = checkSystemctlService("ufw");

    // iptables

    get_exec_path(iptablesLegacyBinary, binpath);

    if(strcmp(binpath, "") != 0)
    {
        iptablesBinary = iptablesLegacyBinary;
        iptablesSaveBinary = iptablesLegacySaveBinary;
        iptablesRestoreBinary = iptablesLegacyRestoreBinary;

        ip6tablesBinary = ip6tablesLegacyBinary;
        ip6tablesSaveBinary = ip6tablesLegacySaveBinary;
        ip6tablesRestoreBinary = ip6tablesLegacyRestoreBinary;

        iptablesAvailable = true;
        iptablesLegacy = true;
    }
    else
    {
        get_exec_path(iptablesCurrentBinary, binpath);

        if(strcmp(binpath, "") != 0)
        {
            iptablesBinary = iptablesCurrentBinary;
            iptablesSaveBinary = iptablesCurrentSaveBinary;
            iptablesRestoreBinary = iptablesCurrentRestoreBinary;

            ip6tablesBinary = ip6tablesCurrentBinary;
            ip6tablesSaveBinary = ip6tablesCurrentSaveBinary;
            ip6tablesRestoreBinary = ip6tablesCurrentRestoreBinary;

            iptablesAvailable = true;
            iptablesLegacy = true;
        }
        else
        {
            iptablesAvailable = false;
            iptablesLegacy = false;
        }
    }

    // nftables

    get_exec_path(nftBinary, binpath);

    if(strcmp(binpath, "") != 0)
        nftablesAvailable = true;
    else
        nftablesAvailable = false;

    // pf

    get_exec_path(pfctlBinary, binpath);

    if(strcmp(binpath, "") != 0)
        pfAvailable = true;
    else
        pfAvailable = false;

    if(setMode(mode) == false)
        filterMode = Mode::UNKNOWN;
}

NetFilter::~NetFilter()
{
    if(charBuffer != NULL)
        free(charBuffer);
}

bool NetFilter::backupFileExists(IP ip)
{
    bool retval = false;
    std::string fileName;

    if(workingDirectory == "")
        return false;

    fileName = workingDirectory;
    fileName += "/";

    switch(filterMode)
    {
        case Mode::IPTABLES:
        {
            if(ip == IP::v4)
                fileName += iptablesSaveFile;
            else
                fileName += ip6tablesSaveFile;
        }
        break;

        case Mode::NFTABLES:
        {
            fileName += nftablesSaveFile;
        }
        break;

        case Mode::PF:
        {
            fileName += pfSaveFile;
        }
        break;

        default:
        {
            return false;
        }
        break;
    }

    if(access(fileName.c_str(), F_OK) == 0)
        retval = true;
    else
        retval = false;

    return retval;
}

bool NetFilter::init()
{
    bool retval = false;

    switch(filterMode)
    {
        case Mode::IPTABLES:
        {
            retval = iptablesSave(IP::v4);

            if(retval == true)
            {
                retval = iptablesSave(IP::v6);
            }
            else
                retval = false;
        }
        break;

        case Mode::NFTABLES:
        {
            retval = nftablesSave();
        }
        break;

        case Mode::PF:
        {
            pfEnable();

            retval = pfSave();
        }
        break;

        default:
        {
            retval = false;
        }
        break;
    }

    return retval;
}

bool NetFilter::restore()
{
    bool retval = false;

    switch(filterMode)
    {
        case Mode::IPTABLES:
        {
            retval = iptablesRestore(IP::v4);

            if(retval == true)
                retval = iptablesRestore(IP::v6);
        }
        break;

        case Mode::NFTABLES:
        {
            retval = nftablesRestore();
        }
        break;

        case Mode::PF:
        {
            retval = pfRestore();
        }
        break;

        default:
        {
            retval = false;
        }
        break;
    }

    return retval;
}

void NetFilter::setup(std::string loopbackIface)
{
    loopbackInterface = loopbackIface;

    switch(filterMode)
    {
        case Mode::IPTABLES:
        {
            iptablesSetup(loopbackIface);
        }
        break;

        case Mode::NFTABLES:
        {
            nftablesSetup(loopbackIface);
        }
        break;

        case Mode::PF:
        {
            pfSetup(loopbackIface);
        }
        break;

        default:
        {
        }
        break;
    }
}

bool NetFilter::addAllowRule(IP ip, Direction direction, std::string interface, Protocol protocol, std::string sourceIP, int sourcePort, std::string destinationIP, int destinationPort)
{
    bool retval = false;
    std::string rule;

    switch(filterMode)
    {
        case Mode::IPTABLES:
        {
            rule = "-A ";

            rule += createIptablesGenericRule(direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);

            rule += " -j ACCEPT";

            iptablesAddRule(ip, rule);

            retval = true;
        }
        break;

        case Mode::NFTABLES:
        {
            rule = "add ";

            rule += createNftablesGenericRule(ip, direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);

            rule += " accept";

            nftablesAddRule(rule);

            retval = true;
        }
        break;

        case Mode::PF:
        {
            rule = "pass ";

            rule += createPfGenericRule(ip, direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);

            pfAddRule(rule);

            retval = true;
        }
        break;

        default:
        {
            retval = false;
        }
        break;
    }

    return retval;
}

bool NetFilter::addRejectRule(IP ip, Direction direction, std::string interface, Protocol protocol, std::string sourceIP, int sourcePort, std::string destinationIP, int destinationPort)
{
    bool retval = false;
    std::string rule;

    switch(filterMode)
    {
        case Mode::IPTABLES:
        {
            rule = "-A ";

            rule += createIptablesGenericRule(direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);

            rule += " -j DROP";

            iptablesAddRule(ip, rule);

            retval = true;
        }
        break;

        case Mode::NFTABLES:
        {
            rule = "add ";

            rule += createNftablesGenericRule(ip, direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);

            rule += " drop";

            nftablesAddRule(rule);

            retval = true;
        }
        break;

        case Mode::PF:
        {
            rule = "block ";

            rule += createPfGenericRule(ip, direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);

            pfAddRule(rule);

            retval = true;
        }
        break;

        default:
        {
            retval = false;
        }
        break;
    }

    return retval;
}

bool NetFilter::commitRules()
{
    bool retval = false;

    switch(filterMode)
    {
        case Mode::IPTABLES:
        {
            retval = iptablesCommit(IP::v4);

            if(retval == true)
                retval = iptablesCommit(IP::v6);
        }
        break;

        case Mode::NFTABLES:
        {
            retval = nftablesCommit();
        }
        break;

        case Mode::PF:
        {
            retval = pfCommit();
        }
        break;

        default:
        {
            retval = false;
        }
        break;
    }

    return retval;
}

bool NetFilter::commitAllowRule(IP ip, Direction direction, std::string interface, Protocol protocol, std::string sourceIP, int sourcePort, std::string destinationIP, int destinationPort)
{
    bool retval = false;
    std::string rule;

    switch(filterMode)
    {
        case Mode::IPTABLES:
        {
            rule = "-I ";

            rule += createIptablesGenericRule(direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);

            rule += " -j ACCEPT";

            iptablesCommitRule(ip, rule);

            // Save rule

            rule = "-A ";

            rule += createIptablesGenericRule(direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);

            rule += " -j ACCEPT";

            iptablesAddRule(ip, rule);

            retval = true;
        }
        break;

        case Mode::NFTABLES:
        {
            rule = "insert ";

            rule += createNftablesGenericRule(ip, direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);

            rule += " accept";

            nftablesCommitRule(rule);

            // save rule

            rule = "add ";

            rule += createNftablesGenericRule(ip, direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);

            rule += " accept";

            nftablesAddRule(rule);

            retval = true;
        }
        break;

        case Mode::PF:
        {
            rule = "pass ";

            rule += createPfGenericRule(ip, direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);

            pfAddRule(rule);

            pfCommit();

            retval = true;
        }
        break;

        default:
        {
            retval = false;
        }
        break;
    }

    return retval;
}

bool NetFilter::commitRejectRule(IP ip, Direction direction, std::string interface, Protocol protocol, std::string sourceIP, int sourcePort, std::string destinationIP, int destinationPort)
{
    bool retval = false;
    std::string rule;

    switch(filterMode)
    {
        case Mode::IPTABLES:
        {
            rule = "-I ";

            rule += createIptablesGenericRule(direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);

            rule += " -j DROP";

            iptablesCommitRule(ip, rule);

            // Save rule

            rule = "-A ";

            rule += createIptablesGenericRule(direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);

            rule += " -j DROP";

            iptablesAddRule(ip, rule);

            retval = true;
        }
        break;

        case Mode::NFTABLES:
        {
            rule = "insert ";

            rule += createNftablesGenericRule(ip, direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);

            rule += " drop";

            nftablesCommitRule(rule);

            // Save rule

            rule = "add ";

            rule += createNftablesGenericRule(ip, direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);

            rule += " drop";

            nftablesAddRule(rule);

            retval = true;
        }
        break;

        case Mode::PF:
        {
            rule = "block ";

            rule += createPfGenericRule(ip, direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);

            pfAddRule(rule);

            pfCommit();

            retval = true;
        }
        break;

        default:
        {
            retval = false;
        }
        break;
    }

    return retval;
}

bool NetFilter::commitRemoveAllowRule(IP ip, Direction direction, std::string interface, Protocol protocol, std::string sourceIP, int sourcePort, std::string destinationIP, int destinationPort)
{
    bool retval = false;
    std::string rule;

    switch(filterMode)
    {
        case Mode::IPTABLES:
        {
            rule = "-D ";

            rule += createIptablesGenericRule(direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);

            rule += " -j ACCEPT";

            iptablesCommitRule(ip, rule);

            // Save rule

            iptablesAddRule(ip, rule);

            retval = true;
        }
        break;

        case Mode::NFTABLES:
        {
            rule = "add ";

            rule += createNftablesGenericRule(ip, direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);

            rule += " accept\n";

            size_t pos = nftablesRules.find(rule);

            if(pos != std::string::npos)
            {
                // Remove this rule from saved rules

                nftablesRules.replace(pos, rule.length(), "");

                retval = nftablesCommit();
            }
            else
                retval = false;
        }
        break;

        case Mode::PF:
        {
            rule = "pass ";

            rule += createPfGenericRule(ip, direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);
            rule += "\n";

            size_t pos = pfRules.find(rule);

            if(pos != std::string::npos)
            {
                // Remove this rule from saved rules

                pfRules.replace(pos, rule.length(), "");

                retval = pfCommit();
            }
            else
                retval = false;
        }
        break;

        default:
        {
            retval = false;
        }
        break;
    }

    return retval;
}

bool NetFilter::commitRemoveRejectRule(IP ip, Direction direction, std::string interface, Protocol protocol, std::string sourceIP, int sourcePort, std::string destinationIP, int destinationPort)
{
    bool retval = false;
    std::string rule;

    switch(filterMode)
    {
        case Mode::IPTABLES:
        {
            rule = "-D ";

            rule += createIptablesGenericRule(direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);

            rule += " -j DROP";

            iptablesCommitRule(ip, rule);

            // Save rule

            iptablesAddRule(ip, rule);

            retval = true;
        }
        break;

        case Mode::NFTABLES:
        {
            rule = "add ";

            rule += createNftablesGenericRule(ip, direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);

            rule += " drop\n";

            size_t pos = nftablesRules.find(rule);

            if(pos != std::string::npos)
            {
                // Remove this rule from saved rules

                nftablesRules.replace(pos, rule.length(), "");

                retval = nftablesCommit();
            }
            else
                retval = false;
        }
        break;

        case Mode::PF:
        {
            rule = "block ";

            rule += createPfGenericRule(ip, direction, interface, protocol, sourceIP, sourcePort, destinationIP, destinationPort);
            rule += "\n";

            size_t pos = pfRules.find(rule);

            if(pos != std::string::npos)
            {
                // Remove this rule from saved rules

                pfRules.replace(pos, rule.length(), "");

                retval = pfCommit();
            }
            else
                retval = false;
        }
        break;

        default:
        {
            retval = false;
        }
        break;
    }

    return retval;
}

bool NetFilter::setMode(Mode mode)
{
    bool retval = false;

    switch(mode)
    {
        case Mode::AUTO:
        {
            if(iptablesAvailable == true)
            {
                filterMode = Mode::IPTABLES;

                retval = true;
            }
            else if(nftablesAvailable == true)
            {
                filterMode = Mode::NFTABLES;

                retval = true;
            }
            else if(pfAvailable == true)
            {
                filterMode = Mode::PF;

                retval = true;
            }
            else
                filterMode = Mode::UNKNOWN;
        }
        break;

        case Mode::IPTABLES:
        {
            if(iptablesAvailable == true)
            {
                filterMode = Mode::IPTABLES;

                retval = true;
            }
            else
                filterMode = Mode::UNKNOWN;
        }
        break;

        case Mode::NFTABLES:
        {
            if(nftablesAvailable == true)
            {
                filterMode = Mode::NFTABLES;

                retval = true;
            }
            else
                filterMode = Mode::UNKNOWN;
        }
        break;

        case Mode::PF:
        {
            if(pfAvailable == true)
            {
                filterMode = Mode::PF;

                retval = true;
            }
            else
                filterMode = Mode::UNKNOWN;
        }
        break;

        default:
        {
            filterMode = Mode::UNKNOWN;
        }
        break;
    }

    return retval;
}

NetFilter::Mode NetFilter::getMode()
{
    return filterMode;
}

std::string NetFilter::getModeDescription()
{
    std::string description;

    switch(filterMode)
    {
        case Mode::IPTABLES:
        {
            description = iptablesBinary;
        }
        break;

        case Mode::NFTABLES:
        {
            description = "nftables";
        }
        break;

        case Mode::PF:
        {
            description = "pf";
        }
        break;

        default:
        {
            description = "unknown";
        }
        break;
    }

    return description;
}

bool NetFilter::addIgnoredInterface(std::string interface)
{
    if(std::find(ignoredInterface.begin(), ignoredInterface.end(), interface) != ignoredInterface.end())
        return false;

    ignoredInterface.push_back(interface);

    switch(filterMode)
    {
        case Mode::IPTABLES:
        {
        }
        break;

        case Mode::NFTABLES:
        {
        }
        break;

        case Mode::PF:
        {
            pfAddIgnoredInterface(interface);
        }
        break;

        default:
        {
        }
        break;
    }

    return true;
}

void NetFilter::clearIgnoredInterfaces()
{
    ignoredInterface.clear();
}

bool NetFilter::checkSystemctlService(std::string name)
{
    bool retval = false;

    get_exec_path(systemctlBinary, binpath);

    if(strcmp(binpath, "") != 0)
    {
        if(execute_process(NULL, NULL, binpath, "is-active", "--quiet", name.c_str(), NULL) == 0)
            retval = true;
        else
            retval = false;
    }
    else
        retval = false;

    return retval;
}

bool NetFilter::isFirewalldRunning()
{
    return firewalldAvailable;
}

bool NetFilter::isUfwRunning()
{
    return ufwAvailable;
}

bool NetFilter::isIPTablesLegacy()
{
    return iptablesLegacy;
}

bool NetFilter::readFile(std::string fname, char *buffer, int size)
{
    bool retval = false;
    FILE *fp;
    struct stat fnamestat;
    int fsize;
    size_t nc;

    if(buffer == NULL || size <= 0)
        return false;

    if(access(fname.c_str(), F_OK) == 0)
    {
        stat(fname.c_str(), &fnamestat);

        fsize = fnamestat.st_size;

        if(fsize < size)
        {
            fp = fopen(fname.c_str(), "r");

            nc = fread(buffer, 1, fsize, fp);

            fclose(fp);

            if(nc > 0)
            {
                buffer[fsize] = '\0';

                retval = true;
            }
            else
                retval = false;
        }
        else
            retval = false;
    }
    else
        retval = false;

    return retval;
}

// iptables

void NetFilter::iptablesResetRules(IP ip)
{
    if(ip == IP::v4)
        iptablesRules = "";
    else
        ip6tablesRules = "";
}

std::string NetFilter::createIptablesGenericRule(Direction direction, std::string interface, Protocol protocol, std::string sourceIP, int sourcePort, std::string destinationIP, int destinationPort)
{
    std::string rule = "";

    if(direction == Direction::INPUT)
        rule += "INPUT";
    else
        rule += "OUTPUT";

    if(interface != "")
    {
        if(direction == Direction::INPUT)
            rule += " -i ";
        else
            rule += " -o ";

        rule += interface;
    }

    if(protocol != Protocol::ANY)
    {
        rule += " -p ";

        if(protocol == Protocol::TCP)
            rule += "tcp";
        else
            rule += "udp";
    }

    if(sourceIP != "")
    {
        rule += " -s " + sourceIP;
    }

    if(sourcePort > 0)
    {
        rule += " --sport ";
        rule += sourcePort;
    }

    if(destinationIP != "")
    {
        rule += " -d " + destinationIP;
    }

    if(destinationPort > 0)
    {
        rule += " --dport ";
        rule += destinationPort;
    }

    return rule;
}

void NetFilter::iptablesAddRule(IP ip, std::string rule)
{
    if(ip == IP::v4)
    {
        iptablesRules += rule;
        iptablesRules += "\n";
    }
    else
    {
        ip6tablesRules += rule;
        ip6tablesRules += "\n";
    }
}

bool NetFilter::iptablesCommitRule(IP ip, std::string rule)
{
    bool retval = false;
    char *exec_args[EXEC_MAX_ARGS];
    int n;

    strcpy(binpath, "");

    if(ip == IP::v4)
        get_exec_path(iptablesBinary, binpath);
    else
        get_exec_path(ip6tablesBinary, binpath);

    if(strcmp(binpath, "") != 0)
    {
        retval = true;

        std::istringstream buf(rule);
        std::istream_iterator<std::string> beg(buf), end;

        std::vector<std::string> tokens(beg, end);

        n = 0;

        exec_args[n++] = binpath;

        for(auto& s: tokens)
        {
            exec_args[n++] = (char *)s.c_str();

            if(n == EXEC_MAX_ARGS)
                return false;
        }

        exec_args[n++] = NULL;

        if(execute_process_args(NULL, NULL, binpath, exec_args) != 0)
            retval = false;
    }
    else
        retval = false;

    return retval;
}

bool NetFilter::iptablesCommit(IP ip)
{
    bool retval = false;
    std::string rules;

    strcpy(binpath, "");

    if(ip == IP::v4)
    {
        get_exec_path(iptablesRestoreBinary, binpath);

        rules = iptablesRules;
    }
    else
    {
        get_exec_path(ip6tablesRestoreBinary, binpath);

        rules = ip6tablesRules;
    }

    if(strcmp(binpath, "") != 0)
    {
        iptablesFlush(ip);

        rules += "-A OUTPUT -j DROP\n";
        rules += "COMMIT\n";

        if(execute_process((char *)rules.c_str(), NULL, binpath, NULL) == 0)
            retval = true;
        else
            retval = false;
    }
    else
        retval = false;

    return retval;
}

bool NetFilter::iptablesSave(IP ip)
{
    bool retval = false;
    std::ofstream dumpFile;
    std::string fileName;

    if(workingDirectory == "")
        return false;

    strcpy(binpath, "");

    fileName = workingDirectory;
    fileName += "/";

    if(ip == IP::v4)
    {
        get_exec_path(iptablesSaveBinary, binpath);

        fileName += iptablesSaveFile;
    }
    else
    {
        get_exec_path(ip6tablesSaveBinary, binpath);

        fileName += ip6tablesSaveFile;
    }

    if(strcmp(binpath, "") != 0)
    {
        if(execute_process(NULL, charBuffer, binpath, NULL) == 0)
        {
            dumpFile.open(fileName);

            if(dumpFile.good())
            {
                dumpFile << charBuffer << std::endl;

                dumpFile.close();

                retval = true;
            }
            else
                retval = false;
        }
        else
            retval = false;
    }
    else
        retval = false;

    return retval;
}

bool NetFilter::iptablesRestore(IP ip)
{
    bool retval = false;
    std::string fileName;

    if(workingDirectory == "")
        return false;

    strcpy(binpath, "");

    fileName = workingDirectory;
    fileName += "/";

    if(ip == IP::v4)
    {
        get_exec_path(iptablesRestoreBinary, binpath);

        fileName += iptablesSaveFile;
    }
    else
    {
        get_exec_path(ip6tablesRestoreBinary, binpath);

        fileName += ip6tablesSaveFile;
    }

    if(strcmp(binpath, "") != 0)
    {
        if(access(fileName.c_str(), F_OK) == 0)
        {
            if(readFile(fileName.c_str(), charBuffer, charBufferSize) == true)
            {
                iptablesFlush(ip);

                if(execute_process(charBuffer, NULL, binpath, NULL) == 0)
                {
                    unlink(fileName.c_str());

                    retval = true;
                }
                else
                    retval = false;
            }
            else
                retval = false;
        }
        else
            retval = false;
    }
    else
        retval = false;

    return retval;
}

bool NetFilter::iptablesFlush(IP ip)
{
    bool retval = false;
    char cmdpath[64];

    strcpy(cmdpath, "");

    if(ip == IP::v4)
        get_exec_path(iptablesBinary, cmdpath);
    else
        get_exec_path(ip6tablesBinary, cmdpath);

    if(strcmp(cmdpath, "") != 0)
    {
        retval = true;

        if(execute_process(NULL, NULL, cmdpath, "-t", "filter", "-F", NULL) != 0)
            retval = false;

        if(execute_process(NULL, NULL, cmdpath, "-t", "nat", "-F", NULL) != 0)
            retval = false;

        if(execute_process(NULL, NULL, cmdpath, "-t", "mangle", "-F", NULL) != 0)
            retval = false;

        if(execute_process(NULL, NULL, cmdpath, "-t", "raw", "-F", NULL) != 0)
            retval = false;

        if(execute_process(NULL, NULL, cmdpath, "-t", "security", "-F", NULL) != 0)
            retval = false;

        if(execute_process(NULL, NULL, cmdpath, "-F", NULL) != 0)
            retval = false;

        if(execute_process(NULL, NULL, cmdpath, "-X", NULL) != 0)
            retval = false;
    }
    else
        retval = false;

    return retval;
}

void NetFilter::iptablesSetup(std::string loopbackIface)
{
    // IPv4

    iptablesResetRules(IP::v4);

    iptablesAddRule(IP::v4, "*mangle");
    iptablesAddRule(IP::v4, ":PREROUTING ACCEPT [0:0]");
    iptablesAddRule(IP::v4, ":INPUT ACCEPT [0:0]");
    iptablesAddRule(IP::v4, ":FORWARD ACCEPT [0:0]");
    iptablesAddRule(IP::v4, ":OUTPUT ACCEPT [0:0]");
    iptablesAddRule(IP::v4, ":POSTROUTING ACCEPT [0:0]");
    iptablesAddRule(IP::v4, "COMMIT");
    iptablesAddRule(IP::v4, "*nat");
    iptablesAddRule(IP::v4, ":PREROUTING ACCEPT [0:0]");
    iptablesAddRule(IP::v4, ":INPUT ACCEPT [0:0]");
    iptablesAddRule(IP::v4, ":OUTPUT ACCEPT [0:0]");
    iptablesAddRule(IP::v4, ":POSTROUTING ACCEPT [0:0]");
    iptablesAddRule(IP::v4, "COMMIT");
    iptablesAddRule(IP::v4, "*filter");
    iptablesAddRule(IP::v4, ":INPUT DROP [0:0]");
    iptablesAddRule(IP::v4, ":FORWARD DROP [0:0]");
    iptablesAddRule(IP::v4, ":OUTPUT DROP [0:0]");

    // Local input

    iptablesAddRule(IP::v4, "-A INPUT -i " + loopbackIface + " -j ACCEPT");

    // Accept DHCP

    iptablesAddRule(IP::v4, "-A INPUT -s 255.255.255.255/32 -j ACCEPT");

    // Accept local network

    iptablesAddRule(IP::v4, "-A INPUT -s 192.168.0.0/16 -d 192.168.0.0/16 -j ACCEPT");
    iptablesAddRule(IP::v4, "-A INPUT -s 10.0.0.0/8 -d 10.0.0.0/8 -j ACCEPT");
    iptablesAddRule(IP::v4, "-A INPUT -s 172.16.0.0/12 -d 172.16.0.0/12 -j ACCEPT");

    // Accept ping

    iptablesAddRule(IP::v4, "-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT");

    // Accept established sessions

    iptablesAddRule(IP::v4, "-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT");

    // Accept all tun interfaces

    iptablesAddRule(IP::v4, "-A INPUT -i tun+ -j ACCEPT");

    // Reject everything else

    iptablesAddRule(IP::v4, "-A INPUT -j DROP");

    // Accept TUN forward

    iptablesAddRule(IP::v4, "-A FORWARD -i tun+ -j ACCEPT");

    // Reject all the other forwarding

    iptablesAddRule(IP::v4, "-A FORWARD -j DROP");

    // Local output

    iptablesAddRule(IP::v4, "-A OUTPUT -o " + loopbackIface + " -j ACCEPT");

    // Accept DHCP

    iptablesAddRule(IP::v4, "-A OUTPUT -d 255.255.255.255/32 -j ACCEPT");

    // Accept local network

    iptablesAddRule(IP::v4, "-A OUTPUT -s 192.168.0.0/16 -d 192.168.0.0/16 -j ACCEPT");
    iptablesAddRule(IP::v4, "-A OUTPUT -s 10.0.0.0/8 -d 10.0.0.0/8 -j ACCEPT");
    iptablesAddRule(IP::v4, "-A OUTPUT -s 172.16.0.0/12 -d 172.16.0.0/12 -j ACCEPT");

    // Allow multicast

    iptablesAddRule(IP::v4, "-A OUTPUT -s 192.168.0.0/16 -d 224.0.0.0/24 -j ACCEPT");
    iptablesAddRule(IP::v4, "-A OUTPUT -s 10.0.0.0/8 -d 224.0.0.0/24 -j ACCEPT");
    iptablesAddRule(IP::v4, "-A OUTPUT -s 172.16.0.0/12 -d 224.0.0.0/24 -j ACCEPT");

    // Simple Service Discovery Protocol address

    iptablesAddRule(IP::v4, "-A OUTPUT -s 192.168.0.0/16 -d 239.255.255.250/32 -j ACCEPT");
    iptablesAddRule(IP::v4, "-A OUTPUT -s 10.0.0.0/8 -d 239.255.255.250/32 -j ACCEPT");
    iptablesAddRule(IP::v4, "-A OUTPUT -s 172.16.0.0/12 -d 239.255.255.250/32 -j ACCEPT");

    // Service Location Protocol version 2 address

    iptablesAddRule(IP::v4, "-A OUTPUT -s 192.168.0.0/16 -d 239.255.255.253/32 -j ACCEPT");
    iptablesAddRule(IP::v4, "-A OUTPUT -s 10.0.0.0/8 -d 239.255.255.253/32 -j ACCEPT");
    iptablesAddRule(IP::v4, "-A OUTPUT -s 172.16.0.0/12 -d 239.255.255.253/32 -j ACCEPT");

    // Allow ping

    // iptablesAddRule(IP::v4, "-A OUTPUT -p icmp -m icmp --icmp-type 0 -j ACCEPT");

    // Allow all TUN interfaces

    iptablesAddRule(IP::v4, "-A OUTPUT -o tun+ -j ACCEPT");

    // Allow established sessions

    iptablesAddRule(IP::v4, "-A OUTPUT -m state --state ESTABLISHED -j ACCEPT");

    // IPv6

    iptablesResetRules(IP::v6);

    iptablesAddRule(IP::v6, "*mangle");
    iptablesAddRule(IP::v6, ":PREROUTING ACCEPT [0:0]");
    iptablesAddRule(IP::v6, ":INPUT ACCEPT [0:0]");
    iptablesAddRule(IP::v6, ":FORWARD ACCEPT [0:0]");
    iptablesAddRule(IP::v6, ":OUTPUT ACCEPT [0:0]");
    iptablesAddRule(IP::v6, ":POSTROUTING ACCEPT [0:0]");
    iptablesAddRule(IP::v6, "COMMIT");
    iptablesAddRule(IP::v6, "*nat");
    iptablesAddRule(IP::v6, ":PREROUTING ACCEPT [0:0]");
    iptablesAddRule(IP::v6, ":INPUT ACCEPT [0:0]");
    iptablesAddRule(IP::v6, ":OUTPUT ACCEPT [0:0]");
    iptablesAddRule(IP::v6, ":POSTROUTING ACCEPT [0:0]");
    iptablesAddRule(IP::v6, "COMMIT");
    iptablesAddRule(IP::v6, "*filter");
    iptablesAddRule(IP::v6, ":INPUT DROP [0:0]");
    iptablesAddRule(IP::v6, ":FORWARD DROP [0:0]");
    iptablesAddRule(IP::v6, ":OUTPUT DROP [0:0]");

    // Accept local network

    iptablesAddRule(IP::v6, "-A INPUT -i " + loopbackIface + " -j ACCEPT");

    // Reject traffic to localhost not coming from local interface

    iptablesAddRule(IP::v6, "-A INPUT -s ::1/128 ! -i " + loopbackIface + " -j REJECT --reject-with icmp6-port-unreachable");

    // Disable processing of any RH0 packet which could allow a ping-pong of packets

    iptablesAddRule(IP::v6, "-A INPUT -m rt --rt-type 0 -j DROP");

    // icmpv6-type:router-advertisement - Rules which are required for your IPv6 address to be properly allocated

    iptablesAddRule(IP::v6, "-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 134 -m hl --hl-eq 255 -j ACCEPT");

    // icmpv6-type:neighbor-solicitation - Rules which are required for your IPv6 address to be properly allocated

    iptablesAddRule(IP::v6, "-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 135 -m hl --hl-eq 255 -j ACCEPT");

    // icmpv6-type:neighbor-advertisement - Rules which are required for your IPv6 address to be properly allocated

    iptablesAddRule(IP::v6, "-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 136 -m hl --hl-eq 255 -j ACCEPT");

    // icmpv6-type:redirect - Rules which are required for your IPv6 address to be properly allocated

    iptablesAddRule(IP::v6, "-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 137 -m hl --hl-eq 255 -j ACCEPT");

    // Allow private network

    iptablesAddRule(IP::v6, "-A INPUT -s fe80::/10 -j ACCEPT");

    // Allow multicast

    iptablesAddRule(IP::v6, "-A INPUT -d ff00::/8 -j ACCEPT");

    // Allow ping

    // iptablesAddRule(IP::v6, "-A INPUT -p ipv6-icmp -j ACCEPT");

    // Allow established sessions

    iptablesAddRule(IP::v6, "-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT");

    // Allow all TUN interfaces

    iptablesAddRule(IP::v6, "-A INPUT -i tun+ -j ACCEPT");

    // Reject everything else

    iptablesAddRule(IP::v6, "-A INPUT -j DROP");

    // Disable processing of any RH0 packet which could allow a ping-pong of packets

    iptablesAddRule(IP::v6, "-A FORWARD -m rt --rt-type 0 -j DROP");

    // Allow TUN forwarding

    iptablesAddRule(IP::v6, "-A FORWARD -i tun+ -j ACCEPT");

    // Reject every other forwarding

    iptablesAddRule(IP::v6, "-A FORWARD -j DROP");

    // Allow local traffic

    iptablesAddRule(IP::v6, "-A OUTPUT -o " + loopbackIface + " -j ACCEPT");

    // Disable processing of any RH0 packet which could allow a ping-pong of packets

    iptablesAddRule(IP::v6, "-A OUTPUT -m rt --rt-type 0 -j DROP");

    // Allow private network

    iptablesAddRule(IP::v6, "-A OUTPUT -s fe80::/10 -j ACCEPT");

    // Allow multicast

    iptablesAddRule(IP::v6, "-A OUTPUT -d ff00::/8 -j ACCEPT");

    // Allow ping

    // iptablesAddRule(IP::v6, "-A OUTPUT -p ipv6-icmp -j ACCEPT");

    // Allow TUN

    iptablesAddRule(IP::v6, "-A OUTPUT -o tun+ -j ACCEPT");

    // Allow established sessions

    iptablesAddRule(IP::v6, "-A OUTPUT -m state --state ESTABLISHED -j ACCEPT");
}

// nftables

void NetFilter::nftablesResetRules()
{
    nftablesRules = "";
}

std::string NetFilter::createNftablesGenericRule(IP ip, Direction direction, std::string interface, Protocol protocol, std::string sourceIP, int sourcePort, std::string destinationIP, int destinationPort)
{
    std::string ipTag, ifTag;
    std::string rule = "rule ";

    ipTag = "ip";

    if(ip == IP::v6)
        ipTag += "6";

    rule += ipTag + " filter ";

    if(direction == Direction::INPUT)
    {
        rule += "INPUT";
        ifTag = "iifname";
    }
    else
    {
        rule += "OUTPUT";
        ifTag = "oifname";
    }

    if(interface != "")
        rule += " " + ifTag + " " + interface;

    if(sourceIP != "")
        rule += " " + ipTag + " saddr " + sourceIP;

    if(destinationIP != "")
        rule += " " + ipTag + " daddr " + destinationIP;

    if(protocol != Protocol::ANY)
    {
        rule += " ";

        if(protocol == Protocol::TCP)
            rule += "tcp";
        else
            rule += "udp";
    }

    if(sourcePort > 0)
    {
        rule += " sport ";
        rule += sourcePort;
    }

    if(destinationPort > 0)
    {
        rule += " dport ";
        rule += destinationPort;
    }

    rule += " counter";

    return rule;
}

void NetFilter::nftablesAddRule(std::string rule)
{
    nftablesRules += rule;
    nftablesRules += "\n";
}

bool NetFilter::nftablesCommitRule(std::string rule)
{
    bool retval = false;
    char *exec_args[EXEC_MAX_ARGS];
    int n;

    strcpy(binpath, "");

    get_exec_path(nftBinary, binpath);

    if(strcmp(binpath, "") != 0)
    {
        retval = true;

        std::istringstream buf(rule);
        std::istream_iterator<std::string> beg(buf), end;

        std::vector<std::string> tokens(beg, end);

        n = 0;

        exec_args[n++] = binpath;

        for(auto& s: tokens)
        {
            exec_args[n++] = (char *)s.c_str();

            if(n == EXEC_MAX_ARGS)
                return false;
        }

        exec_args[n++] = NULL;

        if(execute_process_args(NULL, NULL, binpath, exec_args) != 0)
            retval = false;
    }
    else
        retval = false;

    return retval;
}

bool NetFilter::nftablesCommit()
{
    bool retval = false;
    std::string rules = nftablesRules;

    strcpy(binpath, "");

    get_exec_path(nftBinary, binpath);

    if(strcmp(binpath, "") != 0)
    {
        nftablesFlush();

        rules += "add rule ip filter OUTPUT counter drop\n";
        rules += "add rule ip6 filter OUTPUT counter drop\n";

        if(execute_process((char *)rules.c_str(), NULL, binpath, "-f", "-", NULL) == 0)
            retval = true;
        else
            retval = false;
    }
    else
        retval = false;

    return retval;
}

bool NetFilter::nftablesSave()
{
    bool retval = false;
    std::ofstream dumpFile;
    std::string fileName;

    if(workingDirectory == "")
        return false;

    strcpy(binpath, "");

    fileName = workingDirectory;
    fileName += "/";
    fileName += nftablesSaveFile;

    get_exec_path(nftBinary, binpath);

    if(strcmp(binpath, "") != 0)
    {
        if(execute_process(NULL, charBuffer, binpath, "list", "ruleset", NULL) == 0)
        {
            dumpFile.open(fileName);

            if(dumpFile.good())
            {
                dumpFile << charBuffer << std::endl;

                dumpFile.close();

                retval = true;
            }
            else
                retval = false;
        }
        else
            retval = false;
    }
    else
        retval = false;

    return retval;
}

bool NetFilter::nftablesRestore()
{
    bool retval = false;
    std::string fileName;

    if(workingDirectory == "")
        return false;

    strcpy(binpath, "");

    fileName = workingDirectory;
    fileName += "/";
    fileName += nftablesSaveFile;

    get_exec_path(nftBinary, binpath);

    if(strcmp(binpath, "") != 0)
    {
        if(access(fileName.c_str(), F_OK) == 0)
        {
            if(readFile(fileName.c_str(), charBuffer, charBufferSize) == true)
            {
                nftablesFlush();

                if(execute_process(charBuffer, NULL, binpath, "-f", "-", NULL) == 0)
                {
                    unlink(fileName.c_str());

                    retval = true;
                }
                else
                    retval = false;
            }
            else
                retval = false;
        }
        else
            retval = false;
    }
    else
        retval = false;

    return retval;
}

bool NetFilter::nftablesFlush()
{
    bool retval = false;
    char cmdpath[64];

    strcpy(cmdpath, "");

    get_exec_path(nftBinary, cmdpath);

    if(strcmp(cmdpath, "") != 0)
    {
        retval = true;

        if(execute_process(NULL, NULL, cmdpath, "flush", "ruleset", NULL) != 0)
            retval = false;
    }
    else
        retval = false;

    return retval;
}

void NetFilter::nftablesSetup(std::string loopbackIface)
{
    nftablesResetRules();

    // IPv4

    nftablesAddRule("add table ip mangle");
    nftablesAddRule("add chain ip mangle PREROUTING { type filter hook prerouting priority -150; policy accept; }");
    nftablesAddRule("add chain ip mangle INPUT { type filter hook input priority -150; policy accept; }");
    nftablesAddRule("add chain ip mangle FORWARD { type filter hook forward priority -150; policy accept; }");
    nftablesAddRule("add chain ip mangle OUTPUT { type route hook output priority -150; policy accept; }");
    nftablesAddRule("add chain ip mangle POSTROUTING { type filter hook postrouting priority -150; policy accept; }");
    nftablesAddRule("add table ip nat");
    nftablesAddRule("add chain ip nat PREROUTING { type nat hook prerouting priority -100; policy accept; }");
    nftablesAddRule("add chain ip nat INPUT { type nat hook input priority 100; policy accept; }");
    nftablesAddRule("add chain ip nat OUTPUT { type nat hook output priority -100; policy accept; }");
    nftablesAddRule("add chain ip nat POSTROUTING { type nat hook postrouting priority 100; policy accept; }");
    nftablesAddRule("add table ip filter");
    nftablesAddRule("add chain ip filter INPUT { type filter hook input priority 0; policy drop; }");
    nftablesAddRule("add chain ip filter FORWARD { type filter hook forward priority 0; policy drop; }");
    nftablesAddRule("add chain ip filter OUTPUT { type filter hook output priority 0; policy drop; }");

    // Local input

    nftablesAddRule("add rule ip filter INPUT iifname \"lo\" counter accept");

    // Accept DHCP

    nftablesAddRule("add rule ip filter INPUT ip saddr 255.255.255.255 counter accept");

    // Accept local network

    nftablesAddRule("add rule ip filter INPUT ip saddr 192.168.0.0/16 ip daddr 192.168.0.0/16 counter accept");
    nftablesAddRule("add rule ip filter INPUT ip saddr 10.0.0.0/8 ip daddr 10.0.0.0/8 counter accept");
    nftablesAddRule("add rule ip filter INPUT ip saddr 172.16.0.0/12 ip daddr 172.16.0.0/12 counter accept");

    // Accept ping

    nftablesAddRule("add rule ip filter INPUT icmp type echo-request counter accept");

    // Accept established sessions

    nftablesAddRule("add rule ip filter INPUT ct state related,established  counter accept");

    // Accept all tun interfaces

    nftablesAddRule("add rule ip filter INPUT iifname \"tun*\" counter accept");

    // Reject everything else

    nftablesAddRule("add rule ip filter INPUT counter drop");

    // Accept TUN forward

    nftablesAddRule("add rule ip filter FORWARD iifname \"tun*\" counter accept");

    // Reject all the other forwarding

    nftablesAddRule("add rule ip filter FORWARD counter drop");

    // Local output

    nftablesAddRule("add rule ip filter OUTPUT oifname \"lo\" counter accept");

    // Accept DHCP

    nftablesAddRule("add rule ip filter OUTPUT ip daddr 255.255.255.255 counter accept");

    // Accept local network

    nftablesAddRule("add rule ip filter OUTPUT ip saddr 192.168.0.0/16 ip daddr 192.168.0.0/16 counter accept");
    nftablesAddRule("add rule ip filter OUTPUT ip saddr 10.0.0.0/8 ip daddr 10.0.0.0/8 counter accept");
    nftablesAddRule("add rule ip filter OUTPUT ip saddr 172.16.0.0/12 ip daddr 172.16.0.0/12 counter accept");

    // Allow multicast

    nftablesAddRule("add rule ip filter OUTPUT ip saddr 192.168.0.0/16 ip daddr 224.0.0.0/24 counter accept");
    nftablesAddRule("add rule ip filter OUTPUT ip saddr 10.0.0.0/8 ip daddr 224.0.0.0/24 counter accept");
    nftablesAddRule("add rule ip filter OUTPUT ip saddr 172.16.0.0/12 ip daddr 224.0.0.0/24 counter accept");

    // Simple Service Discovery Protocol address

    nftablesAddRule("add rule ip filter OUTPUT ip saddr 192.168.0.0/16 ip daddr 239.255.255.250 counter accept");
    nftablesAddRule("add rule ip filter OUTPUT ip saddr 10.0.0.0/8 ip daddr 239.255.255.250 counter accept");
    nftablesAddRule("add rule ip filter OUTPUT ip saddr 172.16.0.0/12 ip daddr 239.255.255.250 counter accept");

    // Service Location Protocol version 2 address

    nftablesAddRule("add rule ip filter OUTPUT ip saddr 192.168.0.0/16 ip daddr 239.255.255.253 counter accept");
    nftablesAddRule("add rule ip filter OUTPUT ip saddr 10.0.0.0/8 ip daddr 239.255.255.253 counter accept");
    nftablesAddRule("add rule ip filter OUTPUT ip saddr 172.16.0.0/12 ip daddr 239.255.255.253 counter accept");

    // Allow ping

    // nftablesAddRule("add rule ip filter OUTPUT icmp type echo-reply counter accept");

    // Allow all TUN interfaces

    nftablesAddRule("add rule ip filter OUTPUT oifname \"tun*\" counter accept");

    // Allow established sessions

    nftablesAddRule("add rule ip filter OUTPUT ct state established  counter accept");

    // IPv6

    nftablesAddRule("add table ip6 mangle");
    nftablesAddRule("add chain ip6 mangle PREROUTING { type filter hook prerouting priority -150; policy accept; }");
    nftablesAddRule("add chain ip6 mangle INPUT { type filter hook input priority -150; policy accept; }");
    nftablesAddRule("add chain ip6 mangle FORWARD { type filter hook forward priority -150; policy accept; }");
    nftablesAddRule("add chain ip6 mangle OUTPUT { type route hook output priority -150; policy accept; }");
    nftablesAddRule("add chain ip6 mangle POSTROUTING { type filter hook postrouting priority -150; policy accept; }");
    nftablesAddRule("add table ip6 nat");
    nftablesAddRule("add chain ip6 nat PREROUTING { type nat hook prerouting priority -100; policy accept; }");
    nftablesAddRule("add chain ip6 nat INPUT { type nat hook input priority 100; policy accept; }");
    nftablesAddRule("add chain ip6 nat OUTPUT { type nat hook output priority -100; policy accept; }");
    nftablesAddRule("add chain ip6 nat POSTROUTING { type nat hook postrouting priority 100; policy accept; }");
    nftablesAddRule("add table ip6 filter");
    nftablesAddRule("add chain ip6 filter INPUT { type filter hook input priority 0; policy drop; }");
    nftablesAddRule("add chain ip6 filter FORWARD { type filter hook forward priority 0; policy drop; }");
    nftablesAddRule("add chain ip6 filter OUTPUT { type filter hook output priority 0; policy drop; }");

    // Accept local network

    nftablesAddRule("add rule ip6 filter INPUT iifname \"lo\" counter accept");

    // Reject traffic to localhost not coming from local interface

    nftablesAddRule("add rule ip6 filter INPUT iifname != \"lo\" ip6 saddr ::1 counter reject");

    // Disable processing of any RH0 packet which could allow a ping-pong of packets

    nftablesAddRule("add rule ip6 filter INPUT rt type 0 counter drop");

    // icmpv6-type:router-advertisement - Rules which are required for your IPv6 address to be properly allocated

    nftablesAddRule("add rule ip6 filter INPUT meta l4proto ipv6-icmp icmpv6 type nd-router-advert ip6 hoplimit 255 counter accept");

    // icmpv6-type:neighbor-solicitation - Rules which are required for your IPv6 address to be properly allocated

    nftablesAddRule("add rule ip6 filter INPUT meta l4proto ipv6-icmp icmpv6 type nd-neighbor-solicit ip6 hoplimit 255 counter accept");

    // icmpv6-type:neighbor-advertisement - Rules which are required for your IPv6 address to be properly allocated

    nftablesAddRule("add rule ip6 filter INPUT meta l4proto ipv6-icmp icmpv6 type nd-neighbor-advert ip6 hoplimit 255 counter accept");

    // icmpv6-type:redirect - Rules which are required for your IPv6 address to be properly allocated

    nftablesAddRule("add rule ip6 filter INPUT meta l4proto ipv6-icmp icmpv6 type nd-redirect ip6 hoplimit 255 counter accept");

    // Allow private network

    nftablesAddRule("add rule ip6 filter INPUT ip6 saddr fe80::/10 counter accept");

    // Allow multicast

    nftablesAddRule("add rule ip6 filter INPUT ip6 daddr ff00::/8 counter accept");

    // Allow ping

    // nftablesAddRule("add rule ip6 filter INPUT meta l4proto ipv6-icmp counter accept");

    // Allow established sessions

    nftablesAddRule("add rule ip6 filter INPUT ct state related,established  counter accept");

    // Allow all TUN interfaces

    nftablesAddRule("add rule ip6 filter INPUT iifname \"tun*\" counter accept");

    // Reject everything else

    nftablesAddRule("add rule ip6 filter INPUT counter drop");

    // Disable processing of any RH0 packet which could allow a ping-pong of packets

    nftablesAddRule("add rule ip6 filter FORWARD rt type 0 counter drop");

    // Allow TUN forwarding

    nftablesAddRule("add rule ip6 filter FORWARD iifname \"tun*\" counter accept");

    // Reject every other forwarding

    nftablesAddRule("add rule ip6 filter FORWARD counter drop");

    // Allow local traffic

    nftablesAddRule("add rule ip6 filter OUTPUT oifname \"lo\" counter accept");

    // Disable processing of any RH0 packet which could allow a ping-pong of packets

    nftablesAddRule("add rule ip6 filter OUTPUT rt type 0 counter drop");

    // Allow private network

    nftablesAddRule("add rule ip6 filter OUTPUT ip6 saddr fe80::/10 counter accept");

    // Allow multicast

    nftablesAddRule("add rule ip6 filter OUTPUT ip6 daddr ff00::/8 counter accept");

    // Allow ping

    nftablesAddRule("add rule ip6 filter OUTPUT meta l4proto ipv6-icmp counter accept");

    // Allow TUN

    nftablesAddRule("add rule ip6 filter OUTPUT oifname \"tun*\" counter accept");

    // Allow established sessions

    nftablesAddRule("add rule ip6 filter OUTPUT ct state established  counter accept");
}

// pf

void NetFilter::pfResetRules()
{
    pfRules = "";
}

std::string NetFilter::createPfGenericRule(IP ip, Direction direction, std::string interface, Protocol protocol, std::string sourceIP, int sourcePort, std::string destinationIP, int destinationPort)
{
    std::string ifTag;
    std::string rule = "";

    if(direction == Direction::INPUT)
        rule += "in";
    else
        rule += "out";

    rule += " quick";

    if(interface != "")
        rule += " on " + interface;

    rule += " inet";

    if(ip == IP::v6)
        rule += "6";

    if(protocol != Protocol::ANY)
    {
        rule += " proto ";

        if(protocol == Protocol::TCP)
            rule += "tcp";
        else
            rule += "udp";
    }

    if(sourceIP != "")
    {
        rule += " from " + sourceIP;

        if(sourcePort > 0)
        {
            rule += " port ";
            rule += sourcePort;
        }
    }

    if(destinationIP != "")
    {
        rule += " to " + destinationIP;

        if(destinationPort > 0)
        {
            rule += " port ";
            rule += destinationPort;
        }
    }

    rule += " keep state";

    return rule;
}

void NetFilter::pfAddRule(std::string rule)
{
    pfRules += rule;
    pfRules += "\n";
}

bool NetFilter::pfEnable()
{
    bool retval = false;
    std::string ruleFileName, rules;
    std::ofstream outputFile;

    if(workingDirectory == "")
        return false;

    strcpy(binpath, "");

    get_exec_path(pfctlBinary, binpath);

    if(strcmp(binpath, "") != 0)
    {
        if(execute_process(NULL, NULL, binpath, "-e", NULL) == 0)
            retval = true;
        else
            retval = false;
    }
    else
        retval = false;

    return retval;
}

bool NetFilter::pfCommit()
{
    bool retval = false;
    std::string ruleFileName, rules;
    std::ofstream outputFile;

    if(workingDirectory == "")
        return false;

    rules = pfRules;

    rules += "block all\n";

    ruleFileName = workingDirectory;
    ruleFileName += "/";
    ruleFileName += pfNetFilterRulesFile;

    if(access(ruleFileName.c_str(), F_OK) == 0)
        unlink(ruleFileName.c_str());

    outputFile.open(ruleFileName);

    outputFile << rules << std::endl;

    outputFile.close();

    strcpy(binpath, "");

    get_exec_path(pfctlBinary, binpath);

    if(strcmp(binpath, "") != 0)
    {
        pfFlush();

        if(execute_process(NULL, NULL, binpath, "-f", ruleFileName.c_str(), NULL) == 0)
            retval = true;
        else
            retval = false;
    }
    else
        retval = false;

    if(access(ruleFileName.c_str(), F_OK) == 0)
        unlink(ruleFileName.c_str());

    return retval;
}

bool NetFilter::pfSave()
{
    std::ifstream inputFile;
    std::ofstream outputFile;
    std::string outputFileName;

    if(workingDirectory == "")
        return false;

    if(access(pfConfFile.c_str(), F_OK) != 0)
        return false;

    outputFileName = workingDirectory;
    outputFileName += "/";
    outputFileName += pfSaveFile;

    inputFile.open(pfConfFile);
    outputFile.open(outputFileName);

    outputFile << inputFile.rdbuf();

    inputFile.close();
    outputFile.close();

    return true;
}

bool NetFilter::pfRestore()
{
    bool retval = false;
    std::string fileName;

    if(workingDirectory == "")
        return false;

    strcpy(binpath, "");

    fileName = workingDirectory;
    fileName += "/";
    fileName += pfSaveFile;

    get_exec_path(pfctlBinary, binpath);

    if(strcmp(binpath, "") != 0)
    {
        if(access(fileName.c_str(), F_OK) == 0)
        {
            pfFlush();

            if(execute_process(NULL, NULL, binpath, "-f", fileName.c_str(), NULL) == 0)
            {
                unlink(fileName.c_str());

                retval = true;
            }
            else
                retval = false;
        }
        else
            retval = false;
    }
    else
        retval = false;

    return retval;
}

bool NetFilter::pfFlush()
{
    bool retval = false;
    char cmdpath[64];

    strcpy(cmdpath, "");

    get_exec_path(pfctlBinary, cmdpath);

    if(strcmp(cmdpath, "") != 0)
    {
        retval = true;

        if(execute_process(NULL, NULL, cmdpath, "-F", "all", NULL) != 0)
            retval = false;
    }
    else
        retval = false;

    return retval;
}

void NetFilter::pfSetup(std::string loopbackIface)
{
    pfResetRules();

    pfAddRule("set block-policy drop");
    pfAddRule("set ruleset-optimization basic");

    pfAddRule("set skip on { " + loopbackIface + " }");

    pfAddRule("scrub in all");

    pfAddRule("block in all");
    pfAddRule("block out all");

    // IPv4

    // Local networks

    pfAddRule("pass out quick inet from 192.168.0.0/16 to 192.168.0.0/16");
    pfAddRule("pass in quick inet from 192.168.0.0/16 to 192.168.0.0/16");
    pfAddRule("pass out quick inet from 172.16.0.0/12 to 172.16.0.0/12");
    pfAddRule("pass in quick inet from 172.16.0.0/12 to 172.16.0.0/12");
    pfAddRule("pass out quick inet from 10.0.0.0/8 to 10.0.0.0/8");
    pfAddRule("pass in quick inet from 10.0.0.0/8 to 10.0.0.0/8");

    // Multicast

    pfAddRule("pass out quick inet from 192.168.0.0/16 to 224.0.0.0/24");
    pfAddRule("pass out quick inet from 172.16.0.0/12 to 224.0.0.0/24");
    pfAddRule("pass out quick inet from 10.0.0.0/8 to 224.0.0.0/24");

    // Simple Service Discovery Protocol address

    pfAddRule("pass out quick inet from 192.168.0.0/16 to 239.255.255.250/32");
    pfAddRule("pass out quick inet from 172.16.0.0/12 to 239.255.255.250/32");
    pfAddRule("pass out quick inet from 10.0.0.0/8 to 239.255.255.250/32");

    // Service Location Protocol version 2 address

    pfAddRule("pass out quick inet from 192.168.0.0/16 to 239.255.255.253/32");
    pfAddRule("pass out quick inet from 172.16.0.0/12 to 239.255.255.253/32");
    pfAddRule("pass out quick inet from 10.0.0.0/8 to 239.255.255.253/32");

    // ICMP

    // pfAddRule("pass quick proto icmp");

    // IPv6

    // Local networks

    pfAddRule("pass out quick inet6 from fe80::/10 to fe80::/10");
    pfAddRule("pass in quick inet6 from fe80::/10 to fe80::/10");
    pfAddRule("pass out quick inet6 from ff00::/8 to ff00::/8");
    pfAddRule("pass in quick inet6 from ff00::/8 to ff00::/8");

    // ICMP

    // pfAddRule("pass quick proto icmp6 all");
}


bool NetFilter::pfAddIgnoredInterface(std::string interface)
{
    std::regex skipPattern("set skip on \\{.*\\}");
    std::string replace = "set skip on { " + loopbackInterface;
    std::string out;

    for(std::size_t i=0; i<ignoredInterface.size(); ++i)
    {
        replace += " ";
        replace += ignoredInterface[i];
    }

    replace += " }";

    pfRules = std::regex_replace(pfRules, skipPattern, replace);

    pfCommit();

    return true;
}
