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

void MapSessions::removeClientConnections(ClientHandler *clientSocket)
{
    const char *fnName = "MapSessions::removeClientConnections:";
    QString pubId = _activePolls.key(clientSocket);
    if (! pubId.isEmpty()) {
        qDebug() << fnName << "Client removed from activePolls:" << pubId;
        _activePolls.remove(pubId);
    }

    QString key = _mapClientConnections.key(clientSocket, "");
    if (!key.isEmpty()) {
        _mapClientConnections.remove(key);
        qDebug() << fnName << "Client removed from mapClientConnections:" << clientSocket;
    }
}

QString MapSessions::registerClient(ClientHandler *socket, MapRequest::AuthenticationType authType, QString authToken)
{
    const char *fnName = "MapSessions::registerClient:";
    QString pubId;

    if (authType != MapRequest::AuthNone && !authToken.isEmpty()) {
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << fnName << "Registering client with authType:" << authType
                    << "authToken:" << authToken
                    << "from host:" << socket->peerAddress().toString();
        }
        _mapClientConnections.insert(authToken, socket);

        if (_mapClientRegistry.contains(authToken)) {
            // Already have a publisher-id for this client
            pubId = _mapClientRegistry.value(authToken);
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << fnName << "Already have client configuration with pub-id:" << pubId;
            }
        } else if (_omapdConfig->valueFor("create_client_configurations").toBool()) {
            // Create a new publisher-id for this client
            pubId.setNum(qrand());
            QByteArray pubidhash = QCryptographicHash::hash(pubId.toAscii(), QCryptographicHash::Md5);
            pubId = QString(pubidhash.toHex());
            _mapClientRegistry.insert(authToken,pubId);
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << fnName << "Created client configuration with pub-id:" << _mapClientRegistry.value(authToken);
            }
        }
    }

    return pubId;
}

void MapSessions::checkSessionIdIsActive(MapRequest &clientRequest, QString authToken)
{
    const char *fnName = "MapSessions::checkSessionIdIsActive:";

    /* IFMAP20: 4.4: If the session-id is valid, the server MUST respond with
       a renewSessionResult element.  Otherwise, the server MUST respond with
       an errorResult element, specifying an InvalidSessionID errorCode.
    */
    if (clientRequest.clientSetSessionId()) {
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << fnName << "Using session-id in client request:" << clientRequest.sessionId();
        }
    } else if (_omapdConfig->valueFor("allow_invalid_session_id").toBool()) {
        // NON-STANDARD BEHAVIOR!!!
        // This let's someone curl in a bunch of messages without worrying about
        // maintaining SSRC state.
        qDebug() << fnName << "NON-STANDARD: Ignoring invalid or missing session-id";
        QString publisherId = _mapClientRegistry.value(authToken);
        if (_activeSSRCSessions.contains(publisherId)) {
            clientRequest.setSessionId(_activeSSRCSessions.value(publisherId));
        }
    }

    // Do we have a corresponding publisherId for this session-id?
    QString publisherId = _activeSSRCSessions.key(clientRequest.sessionId());
    if (! publisherId.isEmpty()) {
        // We do have an active SSRC session
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << fnName << "Got session-id:" << clientRequest.sessionId()
                     << "and publisherId:" << publisherId;
        }
    } else {
        // We do NOT have a valid SSRC session
        qDebug() << fnName << "Invalid Session Id for client with authToken:" << authToken;
        clientRequest.setRequestError(MapRequest::IfmapInvalidSessionID);
    }
}

bool MapSessions::validateSessionId(QString sessId, QString authToken)
{
    QString pubIdForSessionId = _activeSSRCSessions.key(sessId);
    QString pubIdForAuthToken = _mapClientRegistry.value(authToken);

    if (pubIdForSessionId.compare(pubIdForAuthToken, Qt::CaseSensitive) == 0)
        return true;
    else
        return false;
}

QString MapSessions::pubIdForAuthToken(QString authToken)
{
    return _mapClientRegistry.value(authToken);
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
