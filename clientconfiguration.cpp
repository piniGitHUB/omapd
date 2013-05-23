/*
clientconfiguration.cpp: Implementation of ClientConfiguration class

Copyright (C) 2011  Sarab D. Mattes <mattes@nixnux.org>

This file is part of omapd.

omapd is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

omapd is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with omapd.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "clientconfiguration.h"

ClientConfiguration::ClientConfiguration()
{
    _haveClientCert = false;
    _authType = MapRequest::AuthNone;
    _authz = OmapdConfig::DenyAll;
}

void ClientConfiguration::createBasicAuthClient(QString clientName, QString username, QString password, OmapdConfig::AuthzOptions authz, QString metadataPolicy)
{
    _authType = MapRequest::AuthBasic;
    _authz = authz;
    _name = clientName;
    _username = username;
    _password = password;
    _metadataPolicy = metadataPolicy;
}

void ClientConfiguration::createCertAuthClient(QString clientName, QString certFile, QString caCertFile, OmapdConfig::AuthzOptions authz, QString metadataPolicy)
{
    _authType = MapRequest::AuthCert;
    _authz = authz;
    _name = clientName;
    _certFileName = certFile;
    _caCertFileName = caCertFile;
    _haveClientCert = true;
    _metadataPolicy = metadataPolicy;
}

void ClientConfiguration::createCAAuthClient(QString clientPrefix, QString issuingCACertFile, QString caCertFile, OmapdConfig::AuthzOptions authz, QString metadataPolicy, QString blacklistDir)
{
    _authType = MapRequest::AuthCACert;
    _authz = authz;
    _name = clientPrefix;
    _caCertFileName = caCertFile;
    _blacklistDirectory = blacklistDir;
    // In this case, _certFileName and _haveClientCert refer to the issuingCACertFile
    _certFileName = issuingCACertFile;
    _haveClientCert = true;
    _metadataPolicy = metadataPolicy;
}
