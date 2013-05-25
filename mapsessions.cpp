/*
mapsessions.cpp: Implementation of MapSessions class

Copyright (C) 2010  Sarab D. Mattes <mattes@nixnux.org>

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

#include "mapsessions.h"
#include "mapclient.h"
#include "clientconfiguration.h"

MapSessions* MapSessions::_instance = 0;

MapSessions* MapSessions::getInstance()
{
    if (_instance == 0) {
        _instance = new MapSessions();
    }
    return _instance;
}

MapSessions::MapSessions(QObject *parent)
    : QObject(parent)
{
    _omapdConfig = OmapdConfig::getInstance();

    // Seed RNG for session-id
    qsrand(QDateTime::currentDateTime().toTime_t());

    // Set pubId starting index
    _pubIdIndex = 1000;

    // Load client configurations
    loadClientConfigurations();

    // Load standard schemas
    if (_omapdConfig->isSet("ifmap_metadata_v11_schema_path")) {
        QString meta11FileName = _omapdConfig->valueFor("ifmap_metadata_v11_schema_path").toString();
        QFile xsd11MetaFile(meta11FileName);
        xsd11MetaFile.open(QIODevice::ReadOnly);
        _ifmapMeta11.load(&xsd11MetaFile, QUrl::fromLocalFile(xsd11MetaFile.fileName()));
        _ifmapMeta11Validator.setSchema(_ifmapMeta11);
    }

    if (_omapdConfig->isSet("ifmap_metadata_v11_schema_path")) {
        QString meta20FileName = _omapdConfig->valueFor("ifmap_metadata_v20_schema_path").toString();
        QFile xsd20MetaFile(meta20FileName);
        xsd20MetaFile.open(QIODevice::ReadOnly);
        _ifmapMeta20.load(&xsd20MetaFile, QUrl::fromLocalFile(xsd20MetaFile.fileName()));
        _ifmapMeta20Validator.setSchema(_ifmapMeta20);
    }
}

MapSessions::~MapSessions()
{
}

void MapSessions::loadClientConfigurations()
{
    QList<ClientConfiguration *> clientConfigurations = _omapdConfig->clientConfigurations();

    QListIterator<ClientConfiguration *> clientIt(clientConfigurations);
    while (clientIt.hasNext()) {
        ClientConfiguration *client = clientIt.next();
        loadClientConfiguration(client);
    }
}

bool MapSessions::loadClientConfiguration(ClientConfiguration *client)
{
    bool clientConfigOk = false;

    QString authToken;

    if (client->authType() == MapRequest::AuthBasic) {

        // TODO: Don't use password as part of authToken
        QString up = client->username() + ":" + client->password();
        authToken = QByteArray(up.toAscii()).toBase64();

        if (!authToken.isEmpty())
            clientConfigOk = true;

    } else if (client->authType() == MapRequest::AuthCert ||
               client->authType() == MapRequest::AuthCACert) {

        if (client->haveClientCert()) {
            QFile certFile(client->certFileName());
            if (!certFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Client:" << client->name()
                        << "has no certificate file:" << certFile.fileName();
            } else {
                QSslCertificate clientCert;
                // Try PEM format fail over to DER; since they are the only 2
                // supported by the QSsl Certificate classes
                clientCert = QSslCertificate(&certFile, QSsl::Pem);
                if ( clientCert.isNull() )
                    clientCert = QSslCertificate(&certFile, QSsl::Der);

                if (!clientCert.isNull()) clientConfigOk = true;

                authToken = ClientHandler::buildDN(clientCert, ClientHandler::Subject);
                if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                    qDebug() << __PRETTY_FUNCTION__ << ":" << "Loaded cert for client named:" << client->name();
                    qDebug() << __PRETTY_FUNCTION__ << ":" << "-- DN:" << authToken;
                }

                if (authToken.isEmpty())
                    clientConfigOk = false;

            }
        }

        // Add CA Certs to default Configuration
        QList<QSslCertificate> caCerts = QSslCertificate::fromPath(client->caCertFileName());
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            foreach(QSslCertificate cert, caCerts) {
                QString issuerDN = ClientHandler::buildDN(cert, ClientHandler::Subject);
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Adding CA Cert to SSL Configuration for client:" << client->name();
                qDebug() << __PRETTY_FUNCTION__ << ":" << "-- DN:" << issuerDN;
            }
        }
        QSslConfiguration defaultConfig = QSslConfiguration::defaultConfiguration();
        defaultConfig.setCaCertificates(defaultConfig.caCertificates()+caCerts);
        QSslConfiguration::setDefaultConfiguration(defaultConfig);
    }

    if (clientConfigOk) {
        if (client->authType() == MapRequest::AuthCACert) {
            MapClient mapClient(authToken, client->authType(), client->authz(), "", client->metadataPolicy());
            _mapClientCAs.insert(authToken, mapClient);
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Created CA Authentication MapClient for configuration named:" << client->name()
                         << "authToken:" << authToken
                         << "authz:" << OmapdConfig::authzOptionsString(client->authz())
                         << "metadataPolicy" << client->metadataPolicy();
            }
        } else {
            QString pubId;
            if (_mapClients.contains(authToken)) {
                // Don't create new publisher-id if replacing client config
                pubId = _mapClients.value(authToken).pubId();
            } else {
                // Create a new publisher-id for this client
                pubId.setNum(_pubIdIndex++);
            }

            MapClient mapClient(authToken, client->authType(), client->authz(), pubId, client->metadataPolicy());
            _mapClients.insert(authToken, mapClient);
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Created MapClient for client configuration named:" << client->name()
                         << "with publisher-id:" << pubId
                         << "authToken:" << authToken
                         << "authz:" << OmapdConfig::authzOptionsString(client->authz())
                         << "metadataPolicy:" << client->metadataPolicy();
            }
        }
    } else {
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Error creating MapClient for client configuration named:" << client->name();
    }

    return clientConfigOk;
}

bool MapSessions::removeClientConfiguration(ClientConfiguration *client)
{
    bool clientConfigOk = false;

    QString authToken;

    if (client->authType() == MapRequest::AuthBasic) {
        // TODO: Don't want mgmt API to need client password

    } else if (client->authType() == MapRequest::AuthCert ||
               client->authType() == MapRequest::AuthCACert) {

        if (client->haveClientCert()) {
            QFile certFile(client->certFileName());
            if (!certFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Client:" << client->name()
                        << "has no certificate file:" << certFile.fileName();
            } else {
                QSslCertificate clientCert;
                // Try PEM format fail over to DER; since they are the only 2
                // supported by the QSsl Certificate classes
                clientCert = QSslCertificate(&certFile, QSsl::Pem);
                if ( clientCert.isNull() )
                    clientCert = QSslCertificate(&certFile, QSsl::Der);

                if (!clientCert.isNull()) clientConfigOk = true;

                authToken = ClientHandler::buildDN(clientCert, ClientHandler::Subject);
                if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                    qDebug() << __PRETTY_FUNCTION__ << ":" << "Loaded cert for client named:" << client->name();
                    qDebug() << __PRETTY_FUNCTION__ << ":" << "-- DN:" << authToken;
                }

                if (authToken.isEmpty())
                    clientConfigOk = false;

            }
        }

        // TODO: Remove CA Certs from default Configuration only if unused by other clients
    }

    if (clientConfigOk) {
        if (client->authType() == MapRequest::AuthCACert) {
            _mapClientCAs.remove(authToken);
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Removed CA Authentication MapClient with authToken" << authToken;
            }
        } else {
            _mapClients.remove(authToken);
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Removed MapClient with authToken" << authToken;
            }
        }
    } else {
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Error removing MapClient";
    }

    return clientConfigOk;
}

QString MapSessions::generateSessionId()
{
    QString sid;
    sid.setNum(qrand());
    QByteArray sidhash = QCryptographicHash::hash(sid.toAscii(), QCryptographicHash::Md5);
    return QString(sidhash.toHex());
}

void MapSessions::removeClientConnections(ClientHandler *clientHandler)
{
    // Is this an SSRC or ARC connection?
    QString authToken = _ssrcConnections.key(clientHandler);
    if (! authToken.isEmpty()) {
        _ssrcConnections.remove(authToken);
    }

    authToken = _activePollConnections.key(clientHandler, "");
    if (! authToken.isEmpty()) {
        _activePollConnections.remove(authToken);

        if (_mapClients.contains(authToken)) {
            MapClient client = _mapClients.take(authToken);
            client.setHasActiveARC(false);
            client.setHasActivePoll(false);
            _mapClients.insert(authToken, client);
        }
    }
}

QString MapSessions::registerMapClient(ClientHandler *clientHandler, MapRequest::AuthenticationType authType, QString authToken)
{
    QString pubId;
    bool registered = false;

    if (authType != MapRequest::AuthNone && !authToken.isEmpty()) {
        if (_mapClients.contains(authToken)) {
            // Already have a publisher-id for this client
            pubId = _mapClients.value(authToken).pubId();
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Already have client configuration with pub-id:" << pubId;
            }

            registered = true;
        } else if (authType == MapRequest::AuthCACert) {
            QStringList compToken = authToken.split("::SEPARATOR::");
            if (!compToken.isEmpty() && _mapClientCAs.contains(compToken.last())) {
                // Create a new publisher-id for this client
                pubId.setNum(_pubIdIndex++);
                // Set the client authorization as determined by CA Cert setting
                OmapdConfig::AuthzOptions authz = _mapClientCAs.value(compToken.last()).authz();
                QString metadataPolicy = _mapClientCAs.value(compToken.last()).metadataPolicy();
                MapClient client(authToken, authType, authz, pubId, metadataPolicy);
                _mapClients.insert(authToken, client);

                registered = true;
                if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                    qDebug() << __PRETTY_FUNCTION__ << ":" << "Created client configuration with pub-id:" << pubId;
                }
            }
        } else if (_omapdConfig->valueFor("create_client_configurations").toBool()) {
            // Create a new publisher-id for this client
            pubId.setNum(_pubIdIndex++);
            OmapdConfig::AuthzOptions authz = _omapdConfig->valueFor("default_authorization").value<OmapdConfig::AuthzOptions>();
            // TODO: Allow application of metadataPolicy to clients created this way
            MapClient client(authToken, authType, authz, pubId, "");
            _mapClients.insert(authToken, client);

            registered = true;
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Created client configuration with pub-id:" << pubId;
            }
        } else {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "ERROR: Client not allowed!";
        }

        if (registered && _omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Registering client with authType:" << authType
                    << "authToken:" << authToken
                    << "from host:" << clientHandler->peerAddress().toString();
        }
    } else {
        qDebug() << __PRETTY_FUNCTION__ << ":" << "ERROR: Attempting to register client with no authentication token and/or no auth type";
    }

    return pubId;
}

bool MapSessions::haveActiveSSRCForClient(QString authToken)
{
    bool haveSSRC = false;

    if (_mapClients.contains(authToken)) {
        haveSSRC = ! _mapClients.value(authToken).sessId().isEmpty();
    }
    return haveSSRC;
}

void MapSessions::removeActiveSSRCForClient(QString authToken)
{
    if (_mapClients.contains(authToken) &&
        _mapClients.value(authToken).hasActiveSSRC()) {
        MapClient client = _mapClients.take(authToken);
        client.setHasActiveSSRC(false);
        client.clearSessId();
        _mapClients.insert(authToken, client);

        _ssrcConnections.remove(authToken);
    }
}

QString MapSessions::sessIdForClient(QString authToken)
{
    QString sessId;
    if (_mapClients.contains(authToken)) {
        sessId = _mapClients.value(authToken).sessId();
    }
    return sessId;
}

QString MapSessions::pubIdForSessId(QString sessId)
{
    QString pubId;
    QList<MapClient> clientList = _mapClients.values();
    bool done = false;
    int i=0;

    while (!done && i<clientList.size()) {
        if (clientList[i].sessId().compare(sessId, Qt::CaseSensitive) == 0) {
            done = true;
            pubId = clientList[i].pubId();
        }
        i++;
    }
    return pubId;
}

QString MapSessions::addActiveSSRCForClient(ClientHandler *clientHandler, QString authToken)
{
    QString sessId;
    if (_mapClients.contains(authToken)) {
        sessId = generateSessionId();
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps))
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Got session-id to use:" << sessId;

        MapClient client = _mapClients.take(authToken);
        client.setSessId(sessId);
        client.setHasActiveSSRC(true);
        _mapClients.insert(authToken, client);

        _ssrcConnections.insert(authToken, clientHandler);
    }
    return sessId;
}

bool MapSessions::validateSessionId(QString sessId, QString authToken)
{
    bool rc = false;
    if (_mapClients.contains(authToken) &&
        _mapClients.value(authToken).hasActiveSSRC() &&
        _mapClients.value(authToken).sessId().compare(sessId, Qt::CaseSensitive) == 0) {
        rc = true;
    }
    return rc;
}

QString MapSessions::pubIdForAuthToken(QString authToken)
{
    QString pubId;
    if (_mapClients.contains(authToken)) {
        pubId = _mapClients.value(authToken).pubId();
    }
    return pubId;
}

OmapdConfig::AuthzOptions MapSessions::authzForAuthToken(QString authToken)
{
    OmapdConfig::AuthzOptions authz = _omapdConfig->valueFor("default_authorization").value<OmapdConfig::AuthzOptions>();
    if (_mapClients.contains(authToken)) {
        authz = _mapClients.value(authToken).authz();
    }
    return authz;
}

bool MapSessions::metadataAuthorizationForAuthToken(QString authToken, QString metaName, QString metaNamespace)
{
    bool clientAuthorized = false;
    if (_mapClients.contains(authToken)) {
        QString policyName = _mapClients.value(authToken).metadataPolicy();

        if (policyName.isEmpty()) {
            // No policy defined for client
            clientAuthorized = true;
        } else {
            QList<VSM> metaAllowed = _omapdConfig->metadataPolicies().values(policyName);
            QListIterator<VSM> i(metaAllowed);
            while (i.hasNext() && !clientAuthorized) {
                VSM metaAllowed = i.next();
                if (metaAllowed.first == metaName && metaAllowed.second == metaNamespace) {
                    clientAuthorized = true;
                }
            }
        }

        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Client authorization for:"
                     << metaNamespace << ":" << metaName
                     << ":" << clientAuthorized;
        }
    }

    return clientAuthorized;
}

bool MapSessions::haveActivePollForClient(QString authToken)
{
    bool rc = false;
    if (_mapClients.contains(authToken)) {
        rc = _mapClients.value(authToken).hasActivePoll();
    }
    return rc;
}

void MapSessions::setActivePollForClient(QString authToken, ClientHandler *pollClientHandler)
{
    if (_mapClients.contains(authToken)) {
        MapClient client = _mapClients.take(authToken);
        client.setHasActivePoll(true);
        _mapClients.insert(authToken, client);

        _activePollConnections.insert(authToken, pollClientHandler);
    }
}

void MapSessions::removeActivePollForClient(QString authToken)
{
    if (_mapClients.contains(authToken) &&
        _mapClients.value(authToken).hasActivePoll()) {
        MapClient client = _mapClients.take(authToken);
        client.setHasActivePoll(false);
        _mapClients.insert(authToken, client);

        _activePollConnections.remove(authToken);
    }
}

ClientHandler* MapSessions::pollConnectionForClient(QString authToken)
{
    ClientHandler* clientHandler = 0;
    if (_mapClients.contains(authToken) &&
        _mapClients.value(authToken).hasActiveARC() &&
        _mapClients.value(authToken).hasActivePoll()) {
        clientHandler = _activePollConnections.value(authToken, 0);
    }
    return clientHandler;
}

ClientHandler* MapSessions::ssrcForClient(QString authToken)
{
    ClientHandler* clientHandler = 0;
    if (_mapClients.contains(authToken) &&
        _mapClients.value(authToken).hasActiveSSRC()) {
        clientHandler = _ssrcConnections.value(authToken, 0);
    }
    return clientHandler;
}

void MapSessions::migrateSSRCForClient(QString authToken, ClientHandler *newSSRCClientHandler)
{
    if (_mapClients.contains(authToken) &&
        _mapClients.value(authToken).hasActiveSSRC()) {
        ClientHandler *oldConnection = _ssrcConnections.take(authToken);
        _ssrcConnections.insert(authToken, newSSRCClientHandler);
        oldConnection->disconnectFromHost();
    }
}

void MapSessions::setActiveARCForClient(QString authToken, ClientHandler *arcClientHandler)
{
    if (_mapClients.contains(authToken) &&
        _mapClients.value(authToken).hasActiveSSRC()) {
        MapClient client = _mapClients.take(authToken);
        client.setHasActiveARC(true);
        _mapClients.insert(authToken, client);

        _arcConnections.insert(authToken, arcClientHandler);
    }
}

bool MapSessions::haveActiveARCForClient(QString authToken)
{
    bool rc = false;
    if (_mapClients.contains(authToken) &&
        _mapClients.value(authToken).hasActiveARC()) {
        rc = true;
    }
    return rc;
}

void MapSessions::removeActiveARCForClient(QString authToken)
{
    if (_mapClients.contains(authToken) &&
        _mapClients.value(authToken).hasActiveARC()) {
        MapClient client = _mapClients.take(authToken);
        client.setHasActiveARC(false);
        _mapClients.insert(authToken, client);

        _arcConnections.remove(authToken);
    }
}

ClientHandler* MapSessions::arcForClient(QString authToken)
{
    ClientHandler* clientHandler = 0;
    if (_mapClients.contains(authToken) &&
        _mapClients.value(authToken).hasActiveARC()) {
        clientHandler = _arcConnections.value(authToken, 0);
    }
    return clientHandler;}

QList<Subscription> MapSessions::subscriptionListForClient(QString authToken)
{
    QList<Subscription> subList;
    if (_mapClients.contains(authToken)) {
        subList = _mapClients.value(authToken).subscriptionList();
    }
    return subList;
}

QList<Subscription> MapSessions::removeSubscriptionListForClient(QString authToken)
{
    QList<Subscription> subList;
    if (_mapClients.contains(authToken)) {
        MapClient client = _mapClients.take(authToken);
        subList = client.subscriptionList();
        client.emptySubscriptionList();
        _mapClients.insert(authToken, client);
    }
    return subList;
}

void MapSessions::setSubscriptionListForClient(QString authToken, QList<Subscription> subList)
{
    if (_mapClients.contains(authToken)) {
        MapClient client = _mapClients.take(authToken);
        client.setSubscriptionList(subList);
        _mapClients.insert(authToken, client);
    }
}

QHash<QString, QList<Subscription> > MapSessions::subscriptionLists()
{
    QHash<QString, QList<Subscription> > allSubLists;

    QHashIterator<QString, MapClient> clientIt(_mapClients);
    while (clientIt.hasNext()) {
        clientIt.next();
        if (clientIt.value().subscriptionList().size() > 0) {
            allSubLists.insert(clientIt.key(), clientIt.value().subscriptionList());
        }
    }
    return allSubLists;
}

bool MapSessions::validateMetadata(Meta aMeta)
{
    bool isValid = false;

    if (_omapdConfig->isSet("ifmap_metadata_v11_schema_path") &&
            aMeta.elementNS().compare(IFMAP_META_NS_1, Qt::CaseSensitive) == 0) {

        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Validating standard IF-MAP v1.1 Metadata";
        }

        if (_ifmapMeta11.isValid()) {
            if (_ifmapMeta11Validator.validate(aMeta.metaXML().toUtf8())) {
                if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
                    qDebug() << __PRETTY_FUNCTION__ << ":" << "Validated standard IF-MAP v1.1 Metadata:" << aMeta.elementName();
                }
                isValid = true;
            } else if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Error validating standard IF-MAP v1.1 Metadata:" << aMeta.elementName();
            }
        } else if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Error with IF-MAP v1.1 Metadata Schema: unable to use schema for validation";
        }

    } else if (_omapdConfig->isSet("ifmap_metadata_v11_schema_path") &&
               aMeta.elementNS().compare(IFMAP_META_NS_2, Qt::CaseSensitive) == 0) {

        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Validating standard IF-MAP v2.0 Metadata";
        }

        if (_ifmapMeta20.isValid()) {
            if (_ifmapMeta20Validator.validate(aMeta.metaXML().toUtf8())) {
                if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
                    qDebug() << __PRETTY_FUNCTION__ << ":" << "Validated standard IF-MAP v2.0 Metadata:" << aMeta.elementName();
                }
                isValid = true;
            } else if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Error validating standard IF-MAP v2.0 Metadata:" << aMeta.elementName();
            }
        } else if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Error with IF-MAP v2.0 Metadata Schema: unable to use schema for validation";
        }

    } else {
        // If we are not validating IF-MAP standard metadata, consider it VSM
        VSM metaNSName;
        metaNSName.first = aMeta.elementName();
        metaNSName.second = aMeta.elementNS();

        if (_vsmRegistry.contains(metaNSName)) {
            Meta::Cardinality registeredCardinality = _vsmRegistry.value(metaNSName);
            if (registeredCardinality == aMeta.cardinality()) {
                isValid = true;
            }
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "VSM registry contains metadata and cardinality matches:" << isValid;
            }
        } else {
            _vsmRegistry.insert(metaNSName, aMeta.cardinality());
            isValid = true;
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Adding cardinality for metadata to VSM registry";
            }
        }
    }

    return isValid;
}
