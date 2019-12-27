/*
 * dnsmanager.hpp
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

#ifndef DNSMANAGER_CLASS_HPP
#define DNSMANAGER_CLASS_HPP

#include <string>

class DNSManager
{
    private:

    std::string resolvDotConf = "/etc/resolv.conf";
    std::string resolvDotConfBkp = "/etc/resolv.conf.dnsmanagerbackup";
    std::string resolvectlCmd, systemdResolveCmd;

    const char *systemctlBinary = "systemctl";
    const char *resolvectlBinary = "resolvectl";
    const char *systemdresolveBinary = "systemd-resolve";

    bool resolvedIsRunning = false;
    bool networkManagerIsRunning = false;

    public:

    enum Error
    {
       OK,
       RESOLV_DOT_CONF_OPEN_ERROR,
       RESOLV_DOT_CONF_RENAME_ERROR,
       RESOLV_DOT_CONF_WRITE_ERROR,
       RESOLV_DOT_CONF_RESTORE_NOT_FOUND,
       RESOLV_DOT_CONF_RESTORE_ERROR,
       RESOLVED_IS_NOT_AVAILABLE,
       RESOLVED_ADD_DNS_ERROR,
       RESOLVED_REVERT_DNS_ERROR,
       NO_RESOLVED_COMMAND
    };
    
    DNSManager(std::string resolvBackupFile = "");
    ~DNSManager();

    void setResolvDotConfBackup(std::string fname);
    Error addAddressToResolvDotConf(const std::string address, bool ipv6);
    Error addAddressToResolved(const char *interface, const char *address, bool ipv6);
    Error addAddressToResolved(const std::string interface, const std::string address, bool ipv6);
    Error revertResolved(const std::string interface);
    Error revertResolved(const char *interface);
    Error revertAllResolved();
    Error restoreResolvDotConf();
    bool resolvDotConfBackupExists();
    bool systemHasResolved();
    bool systemHasNetworkManager();
};

#endif
