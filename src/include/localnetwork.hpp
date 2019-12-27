/*
 * localnetwork.hpp
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

#ifndef LOCALNETWORK_CLASS_HPP
#define LOCALNETWORK_CLASS_HPP

#include <vector>
#include <string>

class LocalNetwork
{
    public:

    LocalNetwork();
    ~LocalNetwork();

    struct IPEntry
    {
        std::string address;
        bool ipv6;
    };

    protected:

    std::vector<IPEntry> localIPaddress;
    std::vector<std::string> localInterface;
    std::string loopbackInterface;

    private:

    void getIpAddresses();
    void getInterfaces();
};

bool operator==(const LocalNetwork::IPEntry& lval, const LocalNetwork::IPEntry& rval);

bool operator!=(const LocalNetwork::IPEntry& lval, const LocalNetwork::IPEntry& rval);

#endif

