#ifndef CLIENTCONFIGURATION_H
#define CLIENTCONFIGURATION_H

#include "omapdconfig.h"
#include "maprequest.h"

class ClientConfiguration
{
public:
    ClientConfiguration();
    void createBasicAuthClient(QString clientName, QString username, QString password, OmapdConfig::AuthzOptions authz);
    void createCertAuthClient(QString clientName, QString certFile, QString caCertFile, OmapdConfig::AuthzOptions authz);
    void createCAAuthClient(QString clientPrefix, QString caCertFile, OmapdConfig::AuthzOptions authz);

    QString name() { return _name; }
    QString username() { return _username; }
    QString password() { return _password; }
    QString certFileName() { return _certFileName; }
    QString caCertFileName() { return _caCertFileName; }
    bool haveClientCert() { return _haveClientCert; }
    MapRequest::AuthenticationType authType() { return _authType; }
    OmapdConfig::AuthzOptions authz() { return _authz; }

private:
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
