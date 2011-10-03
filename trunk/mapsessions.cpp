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

    authToken = _arcConnections.key(clientHandler, "");
    if (! authToken.isEmpty()) {
        _arcConnections.remove(authToken);

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

            _ssrcConnections.insert(authToken, clientHandler);

            registered = true;
        } else if (_omapdConfig->valueFor("create_client_configurations").toBool()) {
            // Create a new publisher-id for this client
            pubId.setNum(_pubIdIndex++);
            MapClient client(authToken, authType, pubId);
            _mapClients.insert(authToken, client);

            _ssrcConnections.insert(authToken, clientHandler);

            registered = true;
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Created client configuration with pub-id:" << pubId;
            }
        } else {

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
        _mapClients.insert(authToken, client);
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

QString MapSessions::addActiveSSRCForClient(QString authToken)
{
    QString sessId;
    if (_mapClients.contains(authToken)) {
        sessId = generateSessionId();
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Got session-id to use:" << sessId;

        MapClient client = _mapClients.take(authToken);
        client.setSessId(sessId);
        client.setHasActiveSSRC(true);
        _mapClients.insert(authToken, client);
    }
    return sessId;
}

void MapSessions::checkSessionIdInRequest(MapRequest &clientRequest, QString authToken)
{
    /* IFMAP20: 4.4: If the session-id is valid, the server MUST respond with
       a renewSessionResult element.  Otherwise, the server MUST respond with
       an errorResult element, specifying an InvalidSessionID errorCode.
    */
    if (clientRequest.clientSetSessionId()) {
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Using session-id in client request:" << clientRequest.sessionId();
        }
    } else if (_omapdConfig->valueFor("allow_invalid_session_id").toBool()) {
        // NON-STANDARD BEHAVIOR!!!
        // This let's someone curl in a bunch of messages without worrying about
        // maintaining SSRC state.
        qDebug() << __PRETTY_FUNCTION__ << ":" << "NON-STANDARD: Ignoring invalid or missing session-id";
        if (_mapClients.contains(authToken)) {
            clientRequest.setSessionId(_mapClients.value(authToken).sessId());
        }
    }

    // Do we have a corresponding publisherId for this session-id?
    if (_mapClients.contains(authToken) &&
        _mapClients.value(authToken).hasActiveSSRC() &&
        _mapClients.value(authToken).sessId().compare(clientRequest.sessionId(), Qt::CaseSensitive) == 0) {
        // We do have an active SSRC session
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Got session-id:" << clientRequest.sessionId()
                     << "and publisherId:" << _mapClients.value(authToken).pubId();
        }
    } else {
        // We do NOT have a valid SSRC session
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Invalid Session Id for client with authToken:" << authToken;
        clientRequest.setRequestError(MapRequest::IfmapInvalidSessionID);
    }
}

bool MapSessions::validateSessionId(QString sessId, QString authToken)
{
    bool rc = false;
    if (_mapClients.contains(authToken) &&
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
        client.setHasActiveARC(true);
        client.setHasActivePoll(true);
        _mapClients.insert(authToken, client);

        _arcConnections.insert(authToken, pollClientHandler);
    }
}

void MapSessions::removeActivePollForClient(QString authToken)
{
    if (_mapClients.contains(authToken) &&
        _mapClients.value(authToken).hasActivePoll()) {
        MapClient client = _mapClients.take(authToken);
        client.setHasActivePoll(false);
        _mapClients.insert(authToken, client);

        _arcConnections.remove(authToken);
    }
}

ClientHandler* MapSessions::pollClientForClient(QString authToken)
{
    ClientHandler* clientHandler = 0;
    if (_mapClients.contains(authToken) &&
        _mapClients.value(authToken).hasActiveARC() &&
        _mapClients.value(authToken).hasActivePoll()) {
        clientHandler = _arcConnections.value(authToken, 0);
    }
    return clientHandler;
}

void MapSessions::setActiveARCForClient(QString authToken)
{
    if (_mapClients.contains(authToken) &&
        _mapClients.value(authToken).hasActiveSSRC()) {
        MapClient client = _mapClients.take(authToken);
        client.setHasActiveARC(true);
        _mapClients.insert(authToken, client);
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
    }
}

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

    if (aMeta.elementNS().compare(IFMAP_META_NS_1, Qt::CaseSensitive) == 0) {
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

    } else if (aMeta.elementNS().compare(IFMAP_META_NS_2, Qt::CaseSensitive) == 0) {
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
