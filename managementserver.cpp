/*
managementserver.cpp: Implementation of ManagementServer class

Copyright (C) 2013  Sarab D. Mattes <mattes@nixnux.org>

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

#include <QTcpSocket>
#include "managementserver.h"

ManagementServer::ManagementServer(MapGraphInterface *mapGraph, QObject *parent) :
    QTcpServer(parent), _mapGraph(mapGraph)
{
    _omapdConfig = OmapdConfig::getInstance();
}

bool ManagementServer::startListening()
{
    bool rc = false;
    QHostAddress listenOn;
    if (listenOn.setAddress(_omapdConfig->valueFor("mgmt_address").toString())) {
        unsigned int port = _omapdConfig->valueFor("mgmt_port").toUInt();

        if (listenOn != QHostAddress::LocalHost && listenOn != QHostAddress::LocalHostIPv6) {
            qDebug() << __PRETTY_FUNCTION__ << ":"
                     << "WARNING: Management interface configured for non-localhost interface:"
                     << listenOn.toString();
        }

        if (listen(listenOn, port)) {
            rc = true;
            this->setMaxPendingConnections(30); // 30 is QTcpServer default

            connect(this, SIGNAL(newConnection()), this, SLOT(handleMgmtConnection()));
        } else {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Error with listen on:" << listenOn.toString()
                    << ":" << port;
        }
    } else {
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Error setting server address";
    }

    return rc;
}

void ManagementServer::handleMgmtConnection()
{
    QTcpSocket *clientConnection = this->nextPendingConnection();

    if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowManagementRequests)) {
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Received management request from:"
                 << clientConnection->peerAddress().toString();
    }

    connect(clientConnection, SIGNAL(disconnected()),
            clientConnection, SLOT(deleteLater()));

    connect(clientConnection, SIGNAL(readyRead()),
            this, SLOT(readMgmtRequest()));
}

void ManagementServer::readMgmtRequest()
{
    QTcpSocket *clientConnection = (QTcpSocket *)sender();

    QByteArray requestData = clientConnection->readLine(128).trimmed();
    if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowManagementRequests)) {
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Received management request:"
                 << requestData;
    }

    if (requestData == "mapdump") {
        _mapGraph->dumpMap();
    } else {
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowManagementRequests)) {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Received unrecognized management request:"
                     << requestData;
        }
    }
}
