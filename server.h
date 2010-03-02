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
#include <QNetworkRequest>
#include <qtsoap.h>

#include "identifier.h"
#include "metadata.h"
#include "mapgraph.h"

enum IFMAP_ERRORCODES_1 {
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
                DebugNone = 0x0000,
                ShowClientOps = 0x0001,
                ShowXML = 0x0002,
                ShowHTTPHeaders = 0x0004,
                ShowHTTPState = 0x0008,
                ShowXMLParsing = 0x0010,
                ShowXMLFilterResults = 0x0020,
                ShowXMLFilterStatements = 0x0040,
                ShowMAPGraphAfterChange = 0x0080
               };
    Q_DECLARE_FLAGS(DebugOptions, Debug);

    enum NonStdBehavior {
                DisableNonStdBehavior = 0x00,
                EnablePubIdHint = 0x01,
                IgnoreSessionId = 0x02,
                DisableHTTPS = 0x04,
                DoNotUseMatchLinksInSearchResults = 0x08
                        };
    Q_DECLARE_FLAGS(NonStdBehaviorOptions, NonStdBehavior);

    enum MapVersionSupport {
               SupportIfmapV11 = 0x00
                           };
    Q_DECLARE_FLAGS(MapVersionSupportOptions, MapVersionSupport);

    Server(MapGraph *mapGraph, quint16 port = 8081, QObject *parent = 0);

public slots:
    void setDebug(Server::DebugOptions debug) { _debug = debug; }
    void setNonStandardBehavior(Server::NonStdBehaviorOptions options) { _nonStdBehavior = options; }
    void setMapVersionSupport(Server::MapVersionSupportOptions options) { _mapVersionSupport = options; }

signals:
    void headerReceived(QTcpSocket *socket, QNetworkRequest requestHdrs);
    void requestMessageReceived(QTcpSocket *socket, QtSoapMessage reqMsg);
    void checkActivePolls();

private:
    int readHeader(QTcpSocket *socket);
    int readRequestData(QTcpSocket *socket);
    void sendHttpResponse(QTcpSocket *socket, int hdrNumber, QString hdrText);
    void sendResponse(QTcpSocket *socket, const QtSoapMessage & respMsg);
    static QString errorString(IFMAP_ERRORCODES_1 error);

    QList<Meta> metaFromNodeList(QDomNodeList metaNodes, Meta::Lifetime lifetime, QString publisherId, IFMAP_ERRORCODES_1 *errorCode);
    Link keyFromNodeList(QDomNodeList ids, int *idCount, IFMAP_ERRORCODES_1 *errorCode);
    Id idFromNode(QDomNode idNode, IFMAP_ERRORCODES_1 *errorCode);
    Id otherIdForLink(Link link, Id targetId);

    QtSoapType* soapResponseForOperation(QString operation, IFMAP_ERRORCODES_1 operationError);
    QtSoapMessage soapResponseMsg(QtSoapType *content, IFMAP_ERRORCODES_1 operationError = ::ErrorNone);
    QtSoapType* soapStructForId(Id id);
    QtSoapStruct* subResultForPollResult(Link link, bool isLink, SearchGraph *sub, QList<Meta> meta, Meta::PublishOperationType publishType);

    QString computePubId(QTcpSocket *socket, QString hint = QString());
    IFMAP_ERRORCODES_1 validateSessionId(QtSoapMessage msg, QTcpSocket *socket, QString *sessionId);

    IFMAP_ERRORCODES_1 searchParameters(QDomNamedNodeMap searchAttrs, int *maxDepth, QString *matchLinks, int *maxSize, QString *resultFilter);

    int filteredMetadata(QList<Meta> metaList, QString filter, QtSoapStruct *metaResult = 0);
    int filteredMetadata(Meta meta, QString filter, QtSoapStruct *metaResult = 0);
    int addSearchResultsWithResultFilter(QtSoapStruct *soapResponse, int maxSize, QString matchLinks, QString resultFilter, QSet<Id> idList, QSet<Link> linkList, IFMAP_ERRORCODES_1 *operationError);
    void buildSearchGraph(Id startId, QString matchLinks, int maxDepth,
                int currentDepth,
                QSet<Id> *idList,
                QSet<Link> *linkList);

    void updateSubscriptions(Link link, bool isLink, QList<Meta> metaChanges, Meta::PublishOperationType publishType);
    void updateSubscriptions(QHash<Id, QList<Meta> > idMetaDeleted, QHash<Link, QList<Meta> > linkMetaDeleted);

    void processNewSession(QTcpSocket *socket, QtSoapMessage reqMsg);
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
};
Q_DECLARE_OPERATORS_FOR_FLAGS(Server::DebugOptions)
Q_DECLARE_OPERATORS_FOR_FLAGS(Server::NonStdBehaviorOptions)
Q_DECLARE_OPERATORS_FOR_FLAGS(Server::MapVersionSupportOptions)

#endif // SERVER_H
