/*
server.cpp: Implementation of Server class

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

#include "server.h"
#include "clienthandler.h"
#include "mapresponse.h"
#include "mapsessions.h"

Server::Server(MapGraphInterface *mapGraph, QObject *parent)
        : QTcpServer(parent), _mapGraph(mapGraph)
{
    _omapdConfig = OmapdConfig::getInstance();
}

bool Server::startListening()
{
    bool rc = false;
    QHostAddress listenOn;
    if (listenOn.setAddress(_omapdConfig->valueFor("address").toString())) {
        unsigned int port = _omapdConfig->valueFor("port").toUInt();

        if (listen(listenOn, port)) {
            rc = true;
            this->setMaxPendingConnections(30); // 30 is QTcpServer default
        } else {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Error with listen on:" << listenOn.toString()
                    << ":" << port;
        }
    } else {
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Error setting server address";
    }

    return rc;
}

void Server::incomingConnection(int socketDescriptor)
{
    ClientHandler *client = new ClientHandler(_mapGraph, this);
    client->setSocketDescriptor(socketDescriptor);
    client->startServerEncryption();

    QObject::connect(client, SIGNAL(disconnected()),
                     this, SLOT(discardClient()));

    connect(client,
            SIGNAL(needToSendPollResponse(ClientHandler*,QByteArray,MapRequest::RequestVersion)),
            this,
            SLOT(sendPollResponseToClient(ClientHandler*,QByteArray,MapRequest::RequestVersion)));

}

void Server::discardClient()
{
    ClientHandler *client = (ClientHandler*)sender();
    qDebug() << __PRETTY_FUNCTION__ << ":" << "client:" << client;

    MapSessions::getInstance()->removeClientFromActivePolls(client);

    client->deleteLater();
}

void Server::sendPollResponseToClient(ClientHandler *client, QByteArray response, MapRequest::RequestVersion reqVersion)
{
    if (client) {
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Client:" << client;
        client->sendPollResponse(response, reqVersion);
    } else {
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Client is null!";
    }

}
