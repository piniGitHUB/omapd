/*
server.h: Definition of Server class

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
#include <qtsoap.h>

#include "identifier.h"
#include "metadata.h"
#include "mapgraph.h"
#include "omapdconfig.h"

enum IFMAP_ERRORCODES {
    ErrorNone = 0,
    IfmapClientSoapFault,
    IfmapAccessDenied,
    IfmapFailure, // Unspecified failure
    IfmapInvalidIdentifier,
    IfmapInvalidIdentifierType,
    IfmapIdentifierTooLong,
    IfmapInvalidMetadata,
    IfmapInvalidMetadataListType,
    IfmapInvalidSchemaVersion,
    IfmapInvalidSessionID,
    IfmapMetadataTooLong,
    IfmapSearchResultsTooBig,
    IfmapPollResultsTooBig,
    IfmapSystemError // Server error
};

class Server : public QTcpServer
{
    Q_OBJECT
public:
    enum Debug {
                DebugNone = 0x000,
                ShowClientOps = 0x0001,
                ShowXML = 0x0002,
                ShowHTTPHeaders = 0x0004,
                ShowHTTPState = 0x0008,
                ShowXMLParsing = 0x0010,
                ShowXMLFilterResults = 0x0020,
                ShowXMLFilterStatements = 0x0040,
                ShowMAPGraphAfterChange = 0x0080,
                ShowRawSocketData = 0x0100
               };
    Q_DECLARE_FLAGS(DebugOptions, Debug);
    static DebugOptions debugOptions(unsigned int dbgValue);
    static QString debugString(Server::DebugOptions debug);

    enum MapVersionSupport {
               SupportNone = 0x00,
               SupportIfmapV10 = 0x01,
               SupportIfmapV11 = 0x02,
                           };
    Q_DECLARE_FLAGS(MapVersionSupportOptions, MapVersionSupport);
    static MapVersionSupportOptions mapVersionSupportOptions(unsigned int value);
    static QString mapVersionSupportString(Server::MapVersionSupportOptions debug);

    Server(MapGraph *mapGraph, QObject *parent = 0);

public slots:
    void setCaCertificates(QList<QSslCertificate> caCerts) { _caCerts = caCerts; }
    void setServerCertificate(QSslCertificate serverCert) { _serverCert = serverCert; }
    void setServerPrivateKey(QSslKey serverKey) { _serverKey = serverKey; }
    QList<QSslCertificate> getCaCertificates() const { return _caCerts; }
    QSslCertificate getServerCertificate() const { return _serverCert; }
signals:
    void headerReceived(QTcpSocket *socket, QNetworkRequest requestHdrs);
    void requestMessageReceived(QTcpSocket *socket, QtSoapMessage reqMsg);
    void checkActivePolls();

private:
    void incomingConnection(int socketDescriptor);
    int readHeader(QTcpSocket *socket);
    int readRequestData(QTcpSocket *socket);
    void sendHttpResponse(QTcpSocket *socket, int hdrNumber, QString hdrText);
    void sendResponse(QTcpSocket *socket, const QtSoapMessage & respMsg);
    static QString errorString(IFMAP_ERRORCODES error);
    bool authorizeClient(QSslSocket *sslSocket);

    void registerClient(QTcpSocket *socket, QString clientKey);

    QList<Meta> metaFromNodeList(QDomNodeList metaNodes, Meta::Lifetime lifetime, QString publisherId, IFMAP_ERRORCODES *errorCode);
    Link keyFromNodeList(QDomNodeList ids, int *idCount, IFMAP_ERRORCODES *errorCode);
    Id idFromNode(QDomNode idNode, IFMAP_ERRORCODES *errorCode);
    Id otherIdForLink(Link link, Id targetId);

    QtSoapType* soapResponseForOperation(QString operation, IFMAP_ERRORCODES operationError);
    QtSoapMessage soapResponseMsg(QtSoapType *content, IFMAP_ERRORCODES operationError = ::ErrorNone);
    QtSoapType* soapStructForId(Id id);

    QString assignPublisherId(QTcpSocket *socket);
    IFMAP_ERRORCODES validateSessionId(QtSoapMessage msg, QTcpSocket *socket, QString *sessionId);

    IFMAP_ERRORCODES searchParameters(QDomNamedNodeMap searchAttrs, int *maxDepth, QString *matchLinks, int *maxSize, QString *resultFilter, QMap<QString, QString> &searchNamespaces);

    int filteredMetadata(QList<Meta> metaList, QString filter, QMap<QString, QString> searchNamespaces, QtSoapStruct *metaResult = 0);
    int filteredMetadata(Meta meta, QString filter, QMap<QString, QString> searchNamespaces, QtSoapStruct *metaResult = 0);
    int addSearchResultsWithResultFilter(QtSoapStruct *soapResponse, int maxSize, QString matchLinks, QString resultFilter, QMap<QString, QString> searchNamespaces, QSet<Id> idList, QSet<Link> linkList, IFMAP_ERRORCODES *operationError);
    void buildSearchGraph(Id startId, QString matchLinks, int maxDepth, QMap<QString, QString> searchNamespaces,
                int currentDepth,
                QSet<Id> *idList,
                QSet<Link> *linkList);

    void updateSubscriptions(Link link, bool isLink, Meta::PublishOperationType publishType);
    void updateSubscriptions(QHash<Id, QList<Meta> > idMetaDeleted, QHash<Link, QList<Meta> > linkMetaDeleted);

    void processNewSession(QTcpSocket *socket);
    void processAttachSession(QTcpSocket *socket, QtSoapMessage reqMsg);
    void processPublish(QTcpSocket *socket, QtSoapMessage reqMsg);
    void processSubscribe(QTcpSocket *socket, QtSoapMessage reqMsg);
    void processSearch(QTcpSocket *socket, QtSoapMessage reqMsg);
    void processPurgePublisher(QTcpSocket *socket, QtSoapMessage reqMsg);
    void processPoll(QTcpSocket *socket, QtSoapMessage reqMsg);
    bool terminateSession(QString sessionId);
    bool terminateARCSession(QString sessionId);

private slots:
    void socketReady();
    void clientSSLVerifyError(const QSslError & error);
    void clientSSLErrors(const QList<QSslError> & errors);
    void newClientConnection();
    void readClient();
    void processHeader(QTcpSocket *socket, QNetworkRequest requestHdrs);
    void discardClient();
    void clientConnState(QAbstractSocket::SocketState sState);
    void sendResultsOnActivePolls();

    void processRequest(QTcpSocket *socket, QtSoapMessage reqMsg);

private:
    OmapdConfig* _omapdConfig;
    MapGraph* _mapGraph;

    QSet<QTcpSocket*> _headersReceived;
    QHash<QString, QTcpSocket*> _activePolls;  // pubId --> QTcpSocket

    // Registry for MAP Clients
    QHash<QString, QTcpSocket*> _mapClientConnections;  // clientKey --> QTcpSocket
    QHash<QString, QString> _mapClientRegistry;  // clientKey --> pubId

    /* TODO: If there are multiple Server instances (e.g. in a thread pool)
       these objects will need to be synchronized across those instances.
       That's why I created a MapSessions class.
    */
    QHash<QString, QList<SearchGraph> > _subscriptionLists;  // pubId --> all subscriptions for pubId
    QHash<QString, QString> _activeARCSessions;  // pubId --> sessId
    QHash<QString, QString> _activeSSRCSessions; // pubId --> sessId

    QList<QSslCertificate> _caCerts;
    QSslCertificate _serverCert;
    QSslKey _serverKey;
    QList<QSslCertificate> _clientCAs;
};
Q_DECLARE_OPERATORS_FOR_FLAGS(Server::DebugOptions)
Q_DECLARE_OPERATORS_FOR_FLAGS(Server::MapVersionSupportOptions)
Q_DECLARE_METATYPE(Server::DebugOptions)
Q_DECLARE_METATYPE(Server::MapVersionSupportOptions)

QDebug operator<<(QDebug dbg, Server::DebugOptions & dbgOptions);
QDebug operator<<(QDebug dbg, Server::MapVersionSupportOptions & dbgOptions);

#endif // SERVER_H
