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
#include <QNetworkRequest>
#include <qtsoap.h>

#include "identifier.h"
#include "metadata.h"
#include "mapgraph.h"

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
                DebugNone = 0x0001,
                ShowClientOps = 0x0002,
                ShowXML = 0x0004,
                ShowHTTPHeaders = 0x0008,
                ShowHTTPState = 0x0010,
                ShowXMLParsing = 0x0020,
                ShowXMLFilterResults = 0x0040,
                ShowXMLFilterStatements = 0x0080,
                ShowMAPGraphAfterChange = 0x0100,
                ShowRawSocketData = 0x0200
               };
    Q_DECLARE_FLAGS(DebugOptions, Debug);

    enum NonStdBehavior {
                DisableNonStdBehavior = 0x01,
                IgnoreSessionId = 0x02,
                DisableHTTPS = 0x04,
                DisableClientCertVerify = 0x08, // Meaningless if DisableHTTPS is set
                DoNotUseMatchLinksInSearchResults = 0x10
                        };
    Q_DECLARE_FLAGS(NonStdBehaviorOptions, NonStdBehavior);

    enum MapVersionSupport {
               SupportIfmapV10 = 0x01,
               SupportIfmapV11 = 0x02,
                           };
    Q_DECLARE_FLAGS(MapVersionSupportOptions, MapVersionSupport);

    enum ServerCapability {
                CreateClientConfigs = 0x01,
                PatchedQtForNamespaceReporting = 0x02
    };
    Q_DECLARE_FLAGS(ServerCapabilityOptions, ServerCapability);

    Server(MapGraph *mapGraph, quint16 port = 8081, QObject *parent = 0);

public slots:
    // config setters
    void setDebug(Server::DebugOptions debug) { _debug = debug; }
    void setNonStandardBehavior(Server::NonStdBehaviorOptions options) { _nonStdBehavior = options; }
    void setMapVersionSupport(Server::MapVersionSupportOptions options) { _mapVersionSupport = options; }
    void setServerCapability(Server::ServerCapabilityOptions options) { _serverCapability = options; }

    // config getters
    Server::DebugOptions getDebug() const {return _debug; }
    Server::NonStdBehaviorOptions getNonStandardBehavior() const { return _nonStdBehavior; }
    Server::MapVersionSupportOptions getMapVersionSupportOptions() const { return _mapVersionSupport; }
    Server::ServerCapabilityOptions getServerCapability() const { return _serverCapability; }

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
    QtSoapStruct* subResultForPollResult(Link link, bool isLink, SearchGraph *sub, QList<Meta> meta, Meta::PublishOperationType publishType);

    QString assignPublisherId(QTcpSocket *socket);
    IFMAP_ERRORCODES validateSessionId(QtSoapMessage msg, QTcpSocket *socket, QString *sessionId);

    IFMAP_ERRORCODES searchParameters(QtSoapMessage msg, QDomNamedNodeMap searchAttrs, int *maxDepth, QString *matchLinks, int *maxSize, QString *resultFilter, QMap<QString, QString> &searchNamespaces);

    int filteredMetadata(QList<Meta> metaList, QString filter, QMap<QString, QString> searchNamespaces, QtSoapStruct *metaResult = 0);
    int filteredMetadata(Meta meta, QString filter, QMap<QString, QString> searchNamespaces, QtSoapStruct *metaResult = 0);
    int addSearchResultsWithResultFilter(QtSoapStruct *soapResponse, int maxSize, QString matchLinks, QString resultFilter, QMap<QString, QString> searchNamespaces, QSet<Id> idList, QSet<Link> linkList, IFMAP_ERRORCODES *operationError);
    void buildSearchGraph(Id startId, QString matchLinks, int maxDepth, QMap<QString, QString> searchNamespaces,
                int currentDepth,
                QSet<Id> *idList,
                QSet<Link> *linkList);

    void updateSubscriptionsWithNotify(Link link, bool isLink, QList<Meta> metaChanges);
    void updateSubscriptions(Link link, bool isLink, Meta::PublishOperationType publishType);
    void updateSubscriptions(QHash<Id, QList<Meta> > idMetaDeleted, QHash<Link, QList<Meta> > linkMetaDeleted);

    void processNewSession(QTcpSocket *socket);
    void processRenewSession(QTcpSocket *socket, QtSoapMessage reqMsg);
    void processEndSession(QTcpSocket *socket, QtSoapMessage reqMsg);
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

    Server::DebugOptions _debug;
    Server::NonStdBehaviorOptions _nonStdBehavior;
    Server::MapVersionSupportOptions _mapVersionSupport;
    Server::ServerCapabilityOptions _serverCapability;
};
Q_DECLARE_OPERATORS_FOR_FLAGS(Server::DebugOptions)
Q_DECLARE_OPERATORS_FOR_FLAGS(Server::NonStdBehaviorOptions)
Q_DECLARE_OPERATORS_FOR_FLAGS(Server::MapVersionSupportOptions)
Q_DECLARE_OPERATORS_FOR_FLAGS(Server::ServerCapabilityOptions)


#endif // SERVER_H
