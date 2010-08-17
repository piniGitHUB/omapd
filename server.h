/*
server.h: Declaration of Server class

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

#ifndef SERVER_H
#define SERVER_H

#include <QTcpServer>
#include <QSslSocket>
#include <QSslKey>
#include <QNetworkRequest>

#include "identifier.h"
#include "metadata.h"
#include "omapdconfig.h"
#include "maprequest.h"
#include "subscription.h"
#include "mapgraphinterface.h"

class MapSessions;
class MapResponse;

class Server : public QTcpServer
{
    Q_OBJECT
public:
    Server(MapGraphInterface *mapGraph, QObject *parent = 0);

public slots:
    void setCaCertificates(QList<QSslCertificate> caCerts) { _caCerts = caCerts; }
    void setServerCertificate(QSslCertificate serverCert) { _serverCert = serverCert; }
    void setServerPrivateKey(QSslKey serverKey) { _serverKey = serverKey; }
    QList<QSslCertificate> getCaCertificates() const { return _caCerts; }
    QSslCertificate getServerCertificate() const { return _serverCert; }
signals:
    void headerReceived(QTcpSocket *socket, QNetworkRequest requestHdrs);
    void clientRequestReceived(QTcpSocket *socket, MapRequest::RequestType reqType, QVariant clientRequest);
    void checkActivePolls();

private:
    void incomingConnection(int socketDescriptor);
    int readHeader(QTcpSocket *socket);
    int readRequestData(QTcpSocket *socket);
    void sendHttpResponse(QTcpSocket *socket, int hdrNumber, QString hdrText);
    bool authorizeClient(QSslSocket *sslSocket);

    QString filteredMetadata(QList<Meta> metaList, QString filter, QMap<QString, QString> searchNamespaces, MapRequest::RequestError &error);
    QString filteredMetadata(Meta meta, QString filter, QMap<QString, QString> searchNamespaces, MapRequest::RequestError &error);
    void collectSearchGraphMetadata(Subscription &sub, SearchResult::ResultType resultType, MapRequest::RequestError &operationError);
#ifdef IFMAP20
    void addUpdateAndDeleteMetadata(Subscription &sub, SearchResult::ResultType resultType, QSet<Id> idList, QSet<Link> linkList, MapRequest::RequestError &operationError);
#endif //IFMAP20
    void buildSearchGraph(Subscription &sub, Id startId, int currentDepth);
    void addIdentifierResult(Subscription &sub, Identifier id, QList<Meta> metaList, SearchResult::ResultType resultType, MapRequest::RequestError &operationError);
    void addLinkResult(Subscription &sub, Link link, QList<Meta> metaList, SearchResult::ResultType resultType, MapRequest::RequestError &operationError);

#ifdef IFMAP20
    void updateSubscriptionsWithNotify(Link link, bool isLink, QList<Meta> metaChanges);
#endif //IFMAP20

    void updateSubscriptions(QHash<Id, QList<Meta> > idMetaDeleted, QHash<Link, QList<Meta> > linkMetaDeleted);
#ifdef IFMAP20
    void updateSubscriptions(Link link, bool isLink, QList<Meta> metaChanges, Meta::PublishOperationType publishType);
#else
    void updateSubscriptions(Link link, bool isLink, Meta::PublishOperationType publishType);
#endif //IFMAP20

    void processNewSession(QTcpSocket *socket, QVariant clientRequest);
#ifdef IFMAP20
    void processRenewSession(QTcpSocket *socket, QVariant clientRequest);
    void processEndSession(QTcpSocket *socket, QVariant clientRequest);
#endif //IFMAP20
    void processAttachSession(QTcpSocket *socket, QVariant clientRequest);
    void processPublish(QTcpSocket *socket, QVariant clientRequest);
    void processSubscribe(QTcpSocket *socket, QVariant clientRequest);
    void processSearch(QTcpSocket *socket, QVariant clientRequest);
    void processPurgePublisher(QTcpSocket *socket, QVariant clientRequest);
    void processPoll(QTcpSocket *socket, QVariant clientRequest);
#ifdef IFMAP20
    bool terminateSession(QString sessionId, MapRequest::RequestVersion requestVersion);
    bool terminateARCSession(QString sessionId, MapRequest::RequestVersion requestVersion);
#else
    bool terminateSession(QString sessionId);
    bool terminateARCSession(QString sessionId);
#endif //IFMAP20

    void sendMapResponse(QTcpSocket *socket, MapResponse &response);

private slots:
    void socketReady();
    void clientSSLVerifyError(const QSslError & error);
    void clientSSLErrors(const QList<QSslError> & errors);
    void readClient();
    void processHeader(QTcpSocket *socket, QNetworkRequest requestHdrs);
    void discardClient();
    void clientConnState(QAbstractSocket::SocketState sState);
    void sendResultsOnActivePolls();

    void processClientRequest(QTcpSocket *socket, MapRequest::RequestType reqType, QVariant clientRequest);

private:
    OmapdConfig* _omapdConfig;
    MapGraphInterface* _mapGraph;
    MapSessions* _mapSessions;

    QSet<QTcpSocket*> _headersReceived;
    QList<QSslCertificate> _caCerts;
    QSslCertificate _serverCert;
    QSslKey _serverKey;
    QSsl::SslProtocol _desiredSSLprotocol;
    QList<QSslCertificate> _clientCAs;
};
#endif // SERVER_H
