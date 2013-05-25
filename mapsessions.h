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
#include <QtXmlPatterns>

#include "omapdconfig.h"
#include "subscription.h"
#include "server.h"
#include "clienthandler.h"

class MapClient;

class MapSessions : public QObject
{
    Q_OBJECT
public:
    static MapSessions* getInstance();

    QString registerMapClient(ClientHandler *socket, MapRequest::AuthenticationType authType, QString authToken);
    QString sessIdForClient(QString authToken);
    QString addActiveSSRCForClient(ClientHandler *clientHandler, QString authToken);

    bool haveActiveSSRCForClient(QString authToken);
    void removeActiveSSRCForClient(QString authToken);

    bool haveActivePollForClient(QString authToken);
    void setActivePollForClient(QString authToken, ClientHandler *pollClientHandler);
    void removeActivePollForClient(QString authToken);
    ClientHandler* pollConnectionForClient(QString authToken);
    ClientHandler* ssrcForClient(QString authToken);
    void migrateSSRCForClient(QString authToken, ClientHandler *newSSRCClientHandler);

    void setActiveARCForClient(QString authToken, ClientHandler *arcClientHandler);
    bool haveActiveARCForClient(QString authToken);
    void removeActiveARCForClient(QString authToken);
    ClientHandler* arcForClient(QString authToken);

    void removeClientConnections(ClientHandler *clientHandler);
    bool validateSessionId(QString sessId, QString authToken);

    QString pubIdForAuthToken(QString authToken);
    QString pubIdForSessId(QString sessId);
    OmapdConfig::AuthzOptions authzForAuthToken(QString authToken);
    bool metadataAuthorizationForAuthToken(QString authToken, QString metaName, QString metaNamespace);

    QList<Subscription> subscriptionListForClient(QString authToken);
    QList<Subscription> removeSubscriptionListForClient(QString authToken);
    void setSubscriptionListForClient(QString authToken, QList<Subscription> subList);
    QHash<QString, QList<Subscription> > subscriptionLists(); // authToken --> subscriptionList for authToken

    bool validateMetadata(Meta aMeta);

    QString generateSessionId();

    bool loadClientConfiguration(ClientConfiguration *client);
    bool removeClientConfiguration(ClientConfiguration *client);

private:
    MapSessions(QObject *parent = 0);
    ~MapSessions();
    void loadClientConfigurations();

    static MapSessions* _instance;

    OmapdConfig *_omapdConfig;

    QHash<QString, MapClient> _mapClients; // authToken --> MapClient
    QHash<QString, MapClient> _mapClientCAs; // CA AuthToken --> MapClient
    // Registry for published vendor specific metadata cardinalities
    QHash<VSM, Meta::Cardinality> _vsmRegistry;

    // Standard IF-MAP schemas
    QXmlSchema _ifmapBase11;
    QXmlSchema _ifmapMeta11;
    QXmlSchema _ifmapBase20;
    QXmlSchema _ifmapMeta20;
    QXmlSchemaValidator _ifmapMeta11Validator;
    QXmlSchemaValidator _ifmapMeta20Validator;

    unsigned int _pubIdIndex;

    QHash<QString, ClientHandler*> _ssrcConnections; // authToken --> ClientHandler
    QHash<QString, ClientHandler*> _arcConnections; // authToken --> ClientHandler
    QHash<QString, ClientHandler*> _activePollConnections; // authToken --> ClientHandler
};

#endif // MAPSESSIONS_H
