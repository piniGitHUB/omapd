/*
mapsessions.h: Declaration of MapSessions Class

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

#ifndef MAPSESSIONS_H
#define MAPSESSIONS_H

#include <QObject>
#include <QtCore>
#include <QtNetwork>

#include "omapdconfig.h"
#include "subscription.h"
#include "server.h"
#include "clienthandler.h"

class MapSessions : public QObject
{
    Q_OBJECT
public:
    static MapSessions* getInstance();

    void removeClientFromActivePolls(ClientHandler *clientSocket);
    void registerClient(ClientHandler *socket, MapRequest::AuthenticationType authType, QString clientKey);
    QString assignPublisherId(QString authToken);
    void validateSessionId(MapRequest &clientRequest, QString authToken);

    QHash<QString, ClientHandler*> _activePolls;  // pubId --> QTcpSocket
    QHash<QString, QList<Subscription> > _subscriptionLists;  // pubId --> all subscriptions for pubId
    QHash<QString, QString> _activeARCSessions;  // pubId --> sessId
    QHash<QString, QString> _activeSSRCSessions; // pubId --> sessId

public slots:
    void foo() {;}

private:
    MapSessions(QObject *parent = 0);
    ~MapSessions();

    static MapSessions* _instance;

    OmapdConfig *_omapdConfig;


    // Registry for MAP Clients
    QHash<QString, const ClientHandler*> _mapClientConnections;  // clientKey --> QTcpSocket
    QHash<QString, QString> _mapClientRegistry;  // clientKey --> pubId

};

#endif // MAPSESSIONS_H
