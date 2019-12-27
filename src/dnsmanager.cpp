/*
 * dnsmanager.cpp
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

#include <fstream>
#include <sys/stat.h>
#include <net/if.h>
#include <unistd.h>
#include <cstring>
#include "include/dnsmanager.hpp"
#include "include/execproc.h"

DNSManager::DNSManager(std::string resolvBackupFile)
{
    char cmd[64];

    networkManagerIsRunning = false;
    resolvedIsRunning = false;

    get_exec_path(systemctlBinary, cmd);

    if(strcmp(cmd, "") != 0)
    {
        if(execute_process(NULL, NULL, cmd, "is-active", "--quiet", "NetworkManager", NULL) == 0)
            networkManagerIsRunning = true;
        
        if(execute_process(NULL, NULL, cmd, "is-active", "--quiet", "systemd-resolved", NULL) == 0)
        {
            resolvedIsRunning = true;

            get_exec_path(resolvectlBinary, cmd);

            if(strcmp(cmd, "") != 0)
                resolvectlCmd = cmd;

            get_exec_path(systemdresolveBinary, cmd);

            if(strcmp(cmd, "") != 0)
                systemdResolveCmd = cmd;

            if(resolvectlCmd != "")
            {
                // flush resolved cache

                execute_process(NULL, NULL, resolvectlCmd.c_str(), "flush-caches", NULL);
            }
            else if(systemdResolveCmd != "")
            {
                // flush resolved cache

                execute_process(NULL, NULL, systemdResolveCmd.c_str(), "--flush-caches", NULL);
            }
        }
    }
    else
    {
        networkManagerIsRunning = false;

        resolvedIsRunning = false;
    }

    setResolvDotConfBackup(resolvBackupFile);
}

DNSManager::~DNSManager()
{
}

void DNSManager::setResolvDotConfBackup(std::string fname)
{
    resolvDotConfBkp = fname;
}

bool DNSManager::systemHasResolved()
{
    return resolvedIsRunning;
}

bool DNSManager::systemHasNetworkManager()
{
    return networkManagerIsRunning;
}

DNSManager::Error DNSManager::addAddressToResolvDotConf(const std::string address, bool ipv6)
{
    std::ofstream flock;

    // If resolv.conf backup does not exist
    // rename resolv.conf to backup and create a new one

    if(access(resolvDotConfBkp.c_str(), F_OK) == -1)
    {
        if(rename(resolvDotConf.c_str(), resolvDotConfBkp.c_str()) != 0)
            return DNSManager::Error::RESOLV_DOT_CONF_RENAME_ERROR;

        flock.open(resolvDotConf.c_str());

        if(flock.fail())
            return DNSManager::Error::RESOLV_DOT_CONF_OPEN_ERROR;

        flock << "#" << std::endl;
        flock << "# Created by AirVPN. Do not edit." << std::endl;
        flock << "#" << std::endl;
        flock << "# Your resolv.conf file is temporarily backed up in " << resolvDotConfBkp << std::endl;
        flock << "# To restore your resolv.conf file you need to log in as root" << std::endl;
        flock << "# and execute the below command from the shell:" << std::endl;
        flock << "#" << std::endl;
        flock << "# mv " << resolvDotConfBkp << " "  << resolvDotConf << std::endl;
        flock << "#" << std::endl << std::endl;

        if(flock.fail() || flock.bad())
            return DNSManager::Error::RESOLV_DOT_CONF_WRITE_ERROR;

        flock.close();

        if(flock.fail())
            return DNSManager::Error::RESOLV_DOT_CONF_OPEN_ERROR;
    }

    flock.open(resolvDotConf, std::ios_base::app);

    if(flock.fail())
        return DNSManager::Error::RESOLV_DOT_CONF_OPEN_ERROR;

    flock << "nameserver " << address << std::endl;

    if(flock.fail() || flock.bad())
        return DNSManager::Error::RESOLV_DOT_CONF_WRITE_ERROR;

    flock.close();

    if(flock.fail())
        return DNSManager::Error::RESOLV_DOT_CONF_OPEN_ERROR;

    return DNSManager::Error::OK;
}

DNSManager::Error DNSManager::addAddressToResolved(const std::string interface, const std::string address, bool ipv6)
{
    return(addAddressToResolved(interface.c_str(), address.c_str(), ipv6));
}

DNSManager::Error DNSManager::addAddressToResolved(const char *interface, const char *address, bool ipv6)
{
    DNSManager::Error retval = DNSManager::Error::RESOLVED_ADD_DNS_ERROR;
    std::string iface, dns, ipv6option;

    if(resolvedIsRunning == false)
        return DNSManager::Error::RESOLVED_IS_NOT_AVAILABLE;

    if(ipv6 == true)
        ipv6option = "-6";
    else
        ipv6option = "-4";

    if(resolvectlCmd != "")
    {
        if(execute_process(NULL, NULL, resolvectlCmd.c_str(), ipv6option.c_str(), "dns", interface, address, NULL) == 0)
            retval = DNSManager::Error::OK;
        else
            retval = DNSManager::Error::RESOLVED_ADD_DNS_ERROR;
    }
    else if(systemdResolveCmd != "")
    {
        iface = "--interface=";
        iface += interface;

        dns = "--set-dns=";
        dns += address;

        if(execute_process(NULL, NULL, systemdResolveCmd.c_str(), ipv6option.c_str(), iface.c_str(), dns.c_str(), NULL) == 0)
            retval = DNSManager::Error::OK;
        else
            retval = DNSManager::Error::RESOLVED_ADD_DNS_ERROR;
    }
    else
        retval = DNSManager::Error::NO_RESOLVED_COMMAND;

    return retval;
}

DNSManager::Error DNSManager::revertAllResolved()
{
    DNSManager::Error retval = DNSManager::Error::OK, revertError;
    struct if_nameindex *ifndx, *iface;

    if(resolvedIsRunning == false)
        return DNSManager::Error::RESOLVED_IS_NOT_AVAILABLE;

    ifndx = if_nameindex();

    if(ifndx != NULL )
    {
        for(iface = ifndx; iface->if_index != 0 || iface->if_name != NULL; iface++)
        {
            if(strcmp(iface->if_name, "lo") != 0)
            {
                revertError = revertResolved(iface->if_name);

                if(revertError != DNSManager::Error::OK)
                    retval = revertError;
            }
        }

        if_freenameindex(ifndx);
    }

    return retval;
}

DNSManager::Error DNSManager::revertResolved(const std::string interface)
{
    return(revertResolved(interface.c_str()));
}

DNSManager::Error DNSManager::revertResolved(const char *interface)
{
    DNSManager::Error retval;
    std::string iface;

    if(resolvedIsRunning == false)
        return DNSManager::Error::RESOLVED_IS_NOT_AVAILABLE;

    if(resolvectlCmd != "")
    {
        if(execute_process(NULL, NULL, resolvectlCmd.c_str(), "revert", interface, NULL) == 0)
            retval = DNSManager::Error::OK;
        else
            retval = DNSManager::Error::RESOLVED_REVERT_DNS_ERROR;
    }
    else if(systemdResolveCmd != "")
    {
        iface = "--interface=";
        iface += interface;

        if(execute_process(NULL, NULL, systemdResolveCmd.c_str(), "--revert", iface.c_str(), NULL) == 0)
            retval = DNSManager::Error::OK;
        else
            retval = DNSManager::Error::RESOLVED_REVERT_DNS_ERROR;
    }
    else
        retval = DNSManager::Error::NO_RESOLVED_COMMAND;

    return retval;
}

DNSManager::Error DNSManager::restoreResolvDotConf(void)
{
    DNSManager::Error res = DNSManager::Error::OK;

    if(access(resolvDotConfBkp.c_str(), F_OK) != -1)
    {
        if(access(resolvDotConf.c_str(), F_OK) != -1)
        {
            if(unlink(resolvDotConf.c_str()) != 0)
                return DNSManager::Error::RESOLV_DOT_CONF_RESTORE_ERROR;

            if(rename(resolvDotConfBkp.c_str(), resolvDotConf.c_str()) != 0)
                return DNSManager::Error::RESOLV_DOT_CONF_RESTORE_ERROR;

        }
        else
            res = DNSManager::Error::RESOLV_DOT_CONF_OPEN_ERROR;
    }
    else
        res = DNSManager::Error::RESOLV_DOT_CONF_RESTORE_NOT_FOUND;

    return res;
}

bool DNSManager::resolvDotConfBackupExists()
{
    bool ret = false;

    if(access(resolvDotConfBkp.c_str(), F_OK) == 0)
        ret = true;

    return ret;
}
