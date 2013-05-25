/*
clientconfiguration.h: Declaration of ClientConfiguration class

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

#ifndef CLIENTCONFIGURATION_H
#define CLIENTCONFIGURATION_H

#include "omapdconfig.h"
#include "maprequest.h"

class ClientConfiguration
{
public:
    ClientConfiguration();
    void createBasicAuthClient(QString clientName, QString username, QString password, OmapdConfig::AuthzOptions authz, QString metadataPolicy);
    void createCertAuthClient(QString clientName, QString certFile, QString caCertFile, OmapdConfig::AuthzOptions authz, QString metadataPolicy);
    void createCAAuthClient(QString clientPrefix, QString issuingCACertFile, QString caCertFile, OmapdConfig::AuthzOptions authz, QString metadataPolicy);

    QString metadataPolicy() { return _metadataPolicy; }
    QString name() { return _name; }
    QString username() { return _username; }
    QString password() { return _password; }
    QString certFileName() { return _certFileName; }
    QString caCertFileName() { return _caCertFileName; }
    bool haveClientCert() { return _haveClientCert; }
    MapRequest::AuthenticationType authType() { return _authType; }
    OmapdConfig::AuthzOptions authz() { return _authz; }

private:
    QString _metadataPolicy;
    QString _username;
    QString _password;
    QString _certFileName;
    QString _caCertFileName;
    bool _haveClientCert;
    MapRequest::AuthenticationType _authType;
    OmapdConfig::AuthzOptions _authz;
    QString _name;
};

#endif // CLIENTCONFIGURATION_H
