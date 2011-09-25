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

void MapSessions::removeClientFromActivePolls(ClientHandler *clientSocket)
{
    const char *fnName = "MapSessions::removeClientFromActivePolls:";
    QString pubId = _activePolls.key(clientSocket);
    if (! pubId.isEmpty()) {
        qDebug() << fnName << "Client disconnected:" << pubId;
        _activePolls.remove(pubId);
    }
}

void MapSessions::registerClient(ClientHandler *socket, MapRequest::AuthenticationType authType, QString authToken)
{
    const char *fnName = "MapSessions::registerClient:";

    if (authType != MapRequest::AuthNone && !authToken.isEmpty()) {
        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << fnName << "Registering client with authType:" << authType
                    << "authToken:" << authToken
                    << "from host:" << socket->peerAddress().toString();
        }
        //FIXME: not sure about this
        _mapClientConnections.insert(authToken, socket);

        if (_mapClientRegistry.contains(authToken)) {
            // Already have a publisher-id for this client
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << fnName << "Already have client configuration with pub-id:" << _mapClientRegistry.value(authToken);
            }
        } else if (_omapdConfig->valueFor("ifmap_create_client_configurations").toBool()) {
            // Create a new publisher-id for this client
            QString pubid;
            pubid.setNum(qrand());
            QByteArray pubidhash = QCryptographicHash::hash(pubid.toAscii(), QCryptographicHash::Md5);
            pubid = QString(pubidhash.toHex());
            _mapClientRegistry.insert(authToken,pubid);
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << fnName << "Created client configuration with pub-id:" << _mapClientRegistry.value(authToken);
            }
        }
    }
}

QString MapSessions::assignPublisherId(QString authToken)
{
    const char *fnName = "MapSessions::assignPublisherId:";
    QString publisherId;

    publisherId = _mapClientRegistry.value(authToken);
    if (publisherId.isEmpty()) {
        qDebug() << fnName << "Error looking up client configuration";
    }

    return publisherId;
}

void MapSessions::validateSessionId(MapRequest &clientRequest, QString authToken)
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
        QString publisherId = assignPublisherId(authToken);
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
        qDebug() << fnName << "Invalid Session Id for client with authToken:" << authToken;
        clientRequest.setRequestError(MapRequest::IfmapInvalidSessionID);
    }
}

