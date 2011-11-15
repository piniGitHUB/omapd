#include "clientconfiguration.h"

ClientConfiguration::ClientConfiguration()
{
    _haveClientCert = false;
    _authType = MapRequest::AuthNone;
    _authz = OmapdConfig::DenyAll;
}

void ClientConfiguration::createBasicAuthClient(QString clientName, QString username, QString password, OmapdConfig::AuthzOptions authz)
{
    _authType = MapRequest::AuthBasic;
    _authz = authz;
    qDebug() << "!!!!!!!!!!!!!!!!!!!!!! authz:" << _authz;
    _name = clientName;
    _username = username;
    _password = password;
}

void ClientConfiguration::createCertAuthClient(QString clientName, QString certFile, QString caCertFile, OmapdConfig::AuthzOptions authz)
{
    _authType = MapRequest::AuthCert;
    _authz = authz;
    _name = clientName;
    _certFileName = certFile;
    _caCertFileName = caCertFile;
    _haveClientCert = true;
}

void ClientConfiguration::createCAAuthClient(QString clientPrefix, QString caCertFile, OmapdConfig::AuthzOptions authz)
{
    _authType = MapRequest::AuthCert;
    _authz = authz;
    _name = clientPrefix;
    _caCertFileName = caCertFile;
    _haveClientCert = false;
}
