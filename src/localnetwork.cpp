/*
 * localnetwork.cpp
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

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <cstring>
#include "include/localnetwork.hpp"

bool operator==(const LocalNetwork::IPEntry& lval, const LocalNetwork::IPEntry& rval)
{
    return lval.address == rval.address && lval.ipv6 == rval.ipv6;
}

bool operator!=(const LocalNetwork::IPEntry& lval, const LocalNetwork::IPEntry& rval)
{
    return !(lval == rval);
}

LocalNetwork::LocalNetwork()
{
    getIpAddresses();

    getInterfaces();
}

LocalNetwork::~LocalNetwork()
{
}

void LocalNetwork::getIpAddresses()
{
    struct ifaddrs *ifAddress = NULL;
    struct ifaddrs *ifa = NULL;
    void *address = NULL;
    char addressBuffer[INET6_ADDRSTRLEN];
    IPEntry ipEntry;

    getifaddrs(&ifAddress);

    for(ifa = ifAddress; ifa != NULL; ifa = ifa->ifa_next)
    {
        if(ifa->ifa_addr)
        {
            if(ifa->ifa_addr->sa_family == AF_INET)
            {
                address = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;

                inet_ntop(AF_INET, address, addressBuffer, INET_ADDRSTRLEN);

                if(strcmp(addressBuffer, "127.0.0.1") != 0)
                {
                    ipEntry.address = addressBuffer;
                    ipEntry.ipv6 = false;

                    localIPaddress.push_back(ipEntry);
                }
            }
            else if(ifa->ifa_addr->sa_family == AF_INET6)
            {
                address = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;

                inet_ntop(AF_INET6, address, addressBuffer, INET6_ADDRSTRLEN);

                if(strcmp(addressBuffer, "::1") != 0)
                {
                    ipEntry.address = addressBuffer;
                    ipEntry.ipv6 = true;

                    localIPaddress.push_back(ipEntry);
                }
            }
        }
    }

    if(ifAddress != NULL)
        freeifaddrs(ifAddress);
}

void LocalNetwork::getInterfaces()
{
    struct if_nameindex *ifndx, *iface;

    localInterface.clear();

    loopbackInterface = "";

    ifndx = if_nameindex();

    if(ifndx != NULL )
    {
        for(iface = ifndx; iface->if_index != 0 || iface->if_name != NULL; iface++)
        {
            if(strcmp(iface->if_name, "lo") != 0 && strcmp(iface->if_name, "lo0") != 0)
                localInterface.push_back(iface->if_name);
            else
                loopbackInterface = iface->if_name;
        }

        if_freenameindex(ifndx);
    }
}
