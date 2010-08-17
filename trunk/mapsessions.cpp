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
}

MapSessions::~MapSessions()
{
}

void MapSessions::removeClientFromActivePolls(QTcpSocket *clientSocket)
{
    const char *fnName = "MapSessions::removeClientFromActivePolls:";
    QString pubId = _activePolls.key(clientSocket);
    if (! pubId.isEmpty()) {
        qDebug() << fnName << "Client disconnected:" << pubId;
        _activePolls.remove(pubId);
    }
}

void MapSessions::registerClient(QTcpSocket *socket, QString clientKey)
{
    const char *fnName = "MapSessions::registerClient:";

    if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
        qDebug() << fnName << "Registering client with key:" << clientKey
                 << "from host:" << socket->peerAddress().toString();
    }
    _mapClientConnections.insert(clientKey, socket);

    if (_mapClientRegistry.contains(clientKey)) {
        // Already have a publisher-id for this client
        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << fnName << "Already have client configuration with pub-id:" << _mapClientRegistry.value(clientKey);
        }
    } else {
        // Create a new publisher-id for this client
        QString pubid;
        pubid.setNum(qrand());
        QByteArray pubidhash = QCryptographicHash::hash(pubid.toAscii(), QCryptographicHash::Md5);
        pubid = QString(pubidhash.toHex());
        _mapClientRegistry.insert(clientKey,pubid);
        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << fnName << "Created client configuration with pub-id:" << _mapClientRegistry.value(clientKey);
        }
    }
}

QString MapSessions::assignPublisherId(QTcpSocket *socket)
{
    const char *fnName = "MapSessions::assignPublisherId:";
    QString publisherId;

    if (_omapdConfig->valueFor("ifmap_create_client_configurations").toBool()) {
        QString clientKey = _mapClientConnections.key(socket);
        publisherId = _mapClientRegistry.value(clientKey);
        if (publisherId.isEmpty()) {
            publisherId = socket->peerAddress().toString();
            qDebug() << fnName << "Error looking up client configuration for client from:" << publisherId;
        }
    } else {
        // Look up client configuration
    }

    return publisherId;
}

void MapSessions::validateSessionId(MapRequest &clientRequest, QTcpSocket *socket)
{
    const char *fnName = "MapSessions::validateSessionId:";

    /* IFMAP20: 4.4: If the session-id is valid, the server MUST respond with
       a renewSessionResult element.  Otherwise, the server MUST respond with
       an errorResult element, specifying an InvalidSessionID errorCode.
    */
    if (clientRequest.clientSetSessionId()) {
        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << fnName << "Using session-id in client request:" << clientRequest.sessionId();
        }
    } else if (_omapdConfig->valueFor("ifmap_allow_invalid_session_id").toBool()) {
        // NON-STANDARD BEHAVIOR!!!
        // This let's someone curl in a bunch of messages without worrying about
        // maintaining SSRC state.
        qDebug() << fnName << "NON-STANDARD: Ignoring invalid or missing session-id";
        QString publisherId = assignPublisherId(socket);
        if (_activeSSRCSessions.contains(publisherId)) {
            clientRequest.setSessionId(_activeSSRCSessions.value(publisherId));
        }
    }

    // Do we have a corresponding publisherId for this session-id?
    QString publisherId = _activeSSRCSessions.key(clientRequest.sessionId());
    if (! publisherId.isEmpty()) {
        // We do have an active SSRC session
        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << fnName << "Got session-id:" << clientRequest.sessionId()
                     << "and publisherId:" << publisherId;
        }
    } else {
        // We do NOT have a valid SSRC session
        qDebug() << fnName << "Invalid Session Id for client at:" << socket->peerAddress().toString();
        clientRequest.setRequestError(MapRequest::IfmapInvalidSessionID);
    }
}

