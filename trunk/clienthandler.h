/*
clienthandler.h: Declaration of ClientHandler class

Copyright (C) 2011  Sarab D. Mattes <mattes@nixnux.org>

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

#ifndef CLIENTHANDLER_H
#define CLIENTHANDLER_H

#include <QSslSocket>
#include <QNetworkRequest>

#include "mapgraphinterface.h"
#include "mapresponse.h"

class ClientParser;
class MapSessions;

class ClientHandler : public QSslSocket
{
    Q_OBJECT
public:
    explicit ClientHandler(MapGraphInterface *mapGraph, QObject *parent = 0);
    ~ClientHandler();
    void sendPollResponse(QByteArray response, MapRequest::RequestVersion reqVersion);
    QString authToken() { return _authToken; }

signals:
    void needToSendPollResponse(ClientHandler *client, QByteArray response, MapRequest::RequestVersion reqVersion);

public slots:
    void handleParseComplete();

private slots:
    void processReadyRead();
    void socketReady();
    void clientSSLVerifyError(const QSslError & error);
    void clientSSLErrors(const QList<QSslError> & errors);
    void clientConnState(QAbstractSocket::SocketState sState);
    void processHeader(QNetworkRequest requestHdrs);

private:
    void setupCrypto();
    void registerCert();
    void sendHttpResponse(int hdrNumber, QString hdrText);
    void sendMapResponse(MapResponse &mapResponse);
    void sendResponse(QByteArray response, MapRequest::RequestVersion reqVersion);
    void processClientRequest();
    void sendResultsOnActivePolls();

    QString filteredMetadata(QList<Meta> metaList, QString filter, QMap<QString, QString> searchNamespaces, MapRequest::RequestError &error);
    QString filteredMetadata(Meta meta, QString filter, QMap<QString, QString> searchNamespaces, MapRequest::RequestError &error);

    void collectSearchGraphMetadata(Subscription &sub, SearchResult::ResultType resultType, MapRequest::RequestError &operationError);
    void addUpdateAndDeleteMetadata(Subscription &sub, SearchResult::ResultType resultType, QSet<Id> idList, QSet<Link> linkList, MapRequest::RequestError &operationError);
    void buildSearchGraph(Subscription &sub, Id startId, int currentDepth);
    void addIdentifierResult(Subscription &sub, Identifier id, QList<Meta> metaList, SearchResult::ResultType resultType, MapRequest::RequestError &operationError);
    void addLinkResult(Subscription &sub, Link link, QList<Meta> metaList, SearchResult::ResultType resultType, MapRequest::RequestError &operationError);

    void updateSubscriptionsWithNotify(Link link, bool isLink, QList<Meta> metaChanges);
    void updateSubscriptions(QHash<Id, QList<Meta> > idMetaDeleted, QHash<Link, QList<Meta> > linkMetaDeleted);
    void updateSubscriptions(Link link, bool isLink, QList<Meta> metaChanges, Meta::PublishOperationType publishType);

    void processNewSession(QVariant clientRequest);
    void processRenewSession(QVariant clientRequest);
    void processEndSession(QVariant clientRequest);
    void processAttachSession(QVariant clientRequest);
    void processPublish(QVariant clientRequest);
    void processSubscribe(QVariant clientRequest);
    void processSearch(QVariant clientRequest);
    void processPurgePublisher(QVariant clientRequest);
    void processPoll(QVariant clientRequest);

    void checkPublishAtomicity(PublishRequest &pubReq, MapRequest::RequestError &requestError);
    QPair< QList<Meta>, QList<Meta> > applyDeleteFilterToMeta(QList<Meta> existingMetaList, PublishOperation pubOper, MapRequest::RequestError &requestError, bool *metadataDeleted = 0);

    bool terminateSession(QString sessionId, MapRequest::RequestVersion requestVersion);
    bool terminateARCSession(QString sessionId, MapRequest::RequestVersion requestVersion);

private:
    OmapdConfig* _omapdConfig;
    MapGraphInterface* _mapGraph;
    MapSessions* _mapSessions;

    ClientParser* _parser;

    MapRequest::AuthenticationType _authType;
    QString _authToken;

    bool _disallowSSLv2;

};

#endif // CLIENTHANDLER_H
