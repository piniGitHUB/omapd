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

#include <QtNetwork>
#include <QtCore>
#include <QtXml>

#include "server.h"

Server::Server(MapGraph *mapGraph, quint16 port, QObject *parent)
        : QTcpServer(parent), _mapGraph(mapGraph)
{
    const char *fnName = "Server::Server:";

    // TODO: Add SSL

    //_debug = Server::ShowHTTPState | Server::ShowXML;
    _debug = Server::DebugNone;
    _nonStdBehavior = Server::EnablePubIdHint | Server::IgnoreSessionId;

    bool listening = listen(QHostAddress::Any, port);
    if (!listening) {
        qDebug() << fnName << "Server will not listen on port:" << port;
    } else {
        this->setMaxPendingConnections(30); // 30 is QTcpServer default

        connect(this, SIGNAL(newConnection()), this, SLOT(newClientConnection()));
        connect(this, SIGNAL(requestMessageReceived(QTcpSocket*,QtSoapMessage)),
                this, SLOT(processRequest(QTcpSocket*,QtSoapMessage)));

        connect(this, SIGNAL(checkSubscriptionsForPolls()),
                this, SLOT(buildPollResults()));

        // Seed RNG for session-ids
        qsrand(QDateTime::currentDateTime().toTime_t());
    }
}

void Server::newClientConnection()
{
    while (this->hasPendingConnections()) {
        QTcpSocket *socket = this->nextPendingConnection();
        connect(socket, SIGNAL(readyRead()), this, SLOT(readClient()));
        connect(socket, SIGNAL(disconnected()), this, SLOT(discardClient()));
        connect(socket, SIGNAL(stateChanged(QAbstractSocket::SocketState)),
                this, SLOT(clientConnState(QAbstractSocket::SocketState)));
    }
}

void Server::clientConnState(QAbstractSocket::SocketState sState)
{
    const char *fnName = "Server::clientConnState:";

    QTcpSocket* socket = (QTcpSocket*)sender();

    if (_debug.testFlag(Server::ShowHTTPState))
        qDebug() << fnName << "socket state for socket:" << socket
                 << "------------->:" << sState;

}

void Server::readClient()
{
    const char *fnName = "Server::readClient:";
    QTcpSocket* socket = (QTcpSocket*)sender();

    bool readError = false;
    qint64 nBytesAvailable = socket->bytesAvailable();
    QByteArray requestByteArr;

    while (nBytesAvailable && !readError) {
        if (! _headersReceived.contains(socket)) {
            // No header received yet
            if (readHeader(socket)) {
                _headersReceived.insert(socket);
            } else {
                // Error - invalid header
                readError = true;
            }
        } else {
            // Have received http header
            if (nBytesAvailable > 0) {
                QByteArray arr;
                arr.resize(nBytesAvailable);
                qint64 read = socket->read(arr.data(), nBytesAvailable);
                arr.resize(read);
                if (arr.size() > 0) {
                    requestByteArr.append(arr);
                }
            }
        }

        nBytesAvailable = socket->bytesAvailable();
    }

    QtSoapMessage reqMsg;
    bool valid = reqMsg.setContent(requestByteArr);
    if (!valid) {
        qDebug() << fnName << "Did not receive full or valid SOAP Message";
    } else {
        /* TODO: If I get a valid SOAP Message, should I remove the socket
           from the set of _headersReceived, or just let this happen in
           discardClient()?
        */
        _headersReceived.remove(socket);

        if (_debug.testFlag(Server::ShowXML))
            qDebug() << fnName << "Request SOAP Envelope:" << endl << reqMsg.toXmlString(2);

        emit requestMessageReceived(socket, reqMsg);
    }

}

int Server::readHeader(QTcpSocket *socket)
{
    const char *fnName = "Server::readHeader:";

    bool end = false;
    QString tmp;
    QString headerStr = QLatin1String("");
    while (!end && socket->canReadLine()) {
        tmp = QString::fromAscii(socket->readLine());
        if (tmp == QLatin1String("\r\n") || tmp == QLatin1String("\n") || tmp.isEmpty())
            end = true;
        else
            headerStr += tmp;
    }

    if (end) {
        emit headerReceived(headerStr);
    }

    if (_debug.testFlag(Server::ShowHTTPHeaders))
        qDebug() << fnName << "headerStr:" << endl << headerStr;

    return headerStr.length();
}

void Server::discardClient()
{
    const char *fnName = "Server::discardClient:";

    QTcpSocket *socket = (QTcpSocket *)sender();

    // Remove socket from set of http headers received
    _headersReceived.remove(socket);

    QString pubId = _activePolls.key(socket);
    if (! pubId.isEmpty()) {
        qDebug() << fnName << "Client disconnected:" << pubId;
        _activePolls.remove(pubId);
    }

    socket->deleteLater();
}

void Server::processRequest(QTcpSocket *socket, QtSoapMessage reqMsg)
{
    const char *fnName = "Server::processRequest:";

    qDebug() << endl << fnName << "Socket:" << socket;

    QtSoapQName arg = reqMsg.method().name();
    qDebug() << fnName << "Received method call:" << arg.name();
    qDebug() << fnName << "Received method namespace:" << arg.uri();

    QString method = arg.name();

    QtSoapStruct soapHdr = reqMsg.header();
    QtSoapSimpleType sessIdElement = (QtSoapSimpleType &)soapHdr.at(QtSoapQName("session-id",IFMAP_NS_1));
    QString reqMsgSessId = sessIdElement.value().toString();

    // TODO: Make publisherId depend on peer identity, not IP address
    QString publisherId = socket->peerAddress().toString();
    // NON-STANDARD BEHAVIOR!!!
    // SPEC: A publisherId hint from the client might be a nice addition to the spec
    //       and could be a unique id the client believes it has.  The server of
    //       course can override the hint.  But this would help a lot when
    //       it is impossible to otherwise distinguish client identities.
    //       However, this would make it possible for a client to publish metadata
    //       in the guise of a different client.
    //       If used, the "pubIdHint" attribute must be in every IF-MAP method.
    if (_nonStdBehavior.testFlag(Server::EnablePubIdHint)) {
        if (reqMsg.method().attributes().contains("pubIdHint")) {
            QString pubIdHint = reqMsg.method().attributes().namedItem("pubIdHint").toAttr().value();
            qDebug() << fnName << "Got pubIdHint:" << pubIdHint << "From publisherId:" << publisherId;
            publisherId += ":";
            publisherId += pubIdHint;
            qDebug() << fnName << "NON-STANDARD: Using pubIdHint attribute in new-session";
        }
    }

    // Default behavior is to respond to a request right now.  A poll without
    // results will not respond right now.
    bool respondNow = true;

    QtSoapMessage respMsg;

    // Remember any encountered errors with request
    IFMAP_ERRORCODES_1 requestError = ErrorNone;

    bool validSessId = false;
    QString existingSSRCSessId = _activeSSRCSessions.value(publisherId);
    if (! reqMsgSessId.isEmpty() && reqMsgSessId == existingSSRCSessId) {
        // session-id in this request matches the existing session-id for this publisherId
        qDebug() << fnName << "Got valid session id in header:" << reqMsgSessId;
        validSessId = true;
    } else if (_nonStdBehavior.testFlag(Server::IgnoreSessionId) &&
               method.compare("new-session", Qt::CaseInsensitive) != 0) {
        // NON-STANDARD BEHAVIOR!!!
        // This let's someone curl in a bunch of messages without worrying about
        // maintaining SSRC state.
        qDebug() << fnName << "NON-STANDARD: Ignoring invalid or missing session-id";
        validSessId = true;
    } else if (! existingSSRCSessId.isEmpty()) {
        // This condition does not make validSessId = true

        // We have an existing session-id for this publisher, but an empty session-id in this request
        // Per IF-MAP1:4.3: An IF-MAP server MUST terminate the SSRC if it
        // receives an invalid session-id in a message from an IF-MAP client.
        _activeSSRCSessions.remove(publisherId);
        qDebug() << fnName << "Terminating existing SSRC session from publisher:" << publisherId;
    }

    if (!validSessId &&
        !( method.compare("new-session", Qt::CaseInsensitive) == 0 ||
           method.compare("attach-session", Qt::CaseInsensitive) == 0) ) {
        // If we do NOT have a valid session id, we still need to process "new-session"
        // and "attach-session" methods separately

        requestError = IfmapInvalidSessionID;
        qDebug() << fnName << "Invalid session-id in request SOAP Header";
        QtSoapStruct *errItem = new QtSoapStruct(QtSoapQName("errorResult", IFMAP_NS_1));
        errItem->setAttribute("errorCode","InvalidSessionID");
        QtSoapSimpleType *eMsg = new QtSoapSimpleType(QtSoapQName("errorString"),
                                 "Invalid session-id in SOAP Header");
        errItem->insert(eMsg);
        respMsg.addBodyItem(errItem);
    } else if (method.compare("new-session", Qt::CaseInsensitive) == 0) {
        QString sessId;
        // Check if we have an SSRC session already for this publisherId
        if (_activeSSRCSessions.contains(publisherId)) {
            // Per IF-MAP1:4.3: If an IF-MAP client sends more than one SOAP
            // request containing a new-session element in the SOAP header,
            // the IF-MAP server MUST respond each time with the same session-id.
            sessId = _activeSSRCSessions.value(publisherId);
        } else {
            sessId.setNum(qrand());
            _activeSSRCSessions.insert(publisherId, sessId);
        }

        // Per IF-MAP1:3.8.4: ARC Session from a previous
        // session MUST be deleted
        terminateARCSession(publisherId);

        QtSoapType *sessIdItem = new QtSoapSimpleType(QtSoapQName("session-id",IFMAP_NS_1),sessId);
        respMsg.addBodyItem(sessIdItem);
        QtSoapType *pubIdItem = new QtSoapSimpleType(QtSoapQName("publisher-id",IFMAP_NS_1),publisherId);
        respMsg.addBodyItem(pubIdItem);

    } else if (method.compare("attach-session", Qt::CaseInsensitive) == 0) {

        QtSoapSimpleType &attachMeth = (QtSoapSimpleType &)reqMsg.method();
        QString sessId = attachMeth.toString();
        qDebug() << fnName << "Got attach-session session-id:" << sessId;

        // 1. Check if we have an ARC session already for this publisherId
        // Per IF-MAP1:4.3: If an IF-MAP server receives a message containing
        // a SOAP header containing an attach-session element that specifies
        // a session which already has an ARC, the IF-MAP server MUST close the
        // older ARC.
        terminateARCSession(publisherId);

        // 2. Verify we have an SSRC session already for this publisherId
        // and that the session-id in the <attachSession> request matches the header
        if (validSessId && reqMsgSessId == sessId) {
            QtSoapType *sessIdItem = new QtSoapSimpleType(QtSoapQName("session-id",IFMAP_NS_1), sessId);
            respMsg.addBodyItem(sessIdItem);
            QtSoapType *pubIdItem = new QtSoapSimpleType(QtSoapQName("publisher-id",IFMAP_NS_1), publisherId);
            respMsg.addBodyItem(pubIdItem);

            _activeARCSessions.insert(publisherId, sessId);
            qDebug() << fnName << "Adding ARC session for publisher:" << publisherId;
        } else {
            qDebug() << fnName << "No valid SSRC session for publisher:" << publisherId;
            requestError = IfmapInvalidSessionID;
            QtSoapType *attachErrorResponse = soapResponseForOperation(method, requestError);
            respMsg.addBodyItem(attachErrorResponse);
        }

    } else if (method.compare("publish", Qt::CaseInsensitive) == 0 && validSessId) {
        QtSoapStruct &pubMeth = (QtSoapStruct &)reqMsg.method();

        // TODO: per IF-MAP1:3.8.1.3: The entire
        //       publish operation MUST fail if any sub-operation fails.
        //       So, we should first validate to make sure everything looks ok.
        //requestError = validate(pubMeth);

        if (!requestError) {
            for (QtSoapStructIterator it(pubMeth); it.current() && !requestError; ++it) {
                QtSoapStruct *pubItem = (QtSoapStruct *)it.data();
                QString pubOperation = pubItem->name().name();
                qDebug() << fnName << "Publish operation:" << pubOperation;
                if (pubOperation.compare("update", Qt::CaseInsensitive) == 0) {

                    QDomDocument doc("placeholder");
                    QDomElement el = pubItem->toDomElement(doc);
                    doc.appendChild(el);

                    QDomNodeList meta = doc.elementsByTagName("metadata").at(0).childNodes();
                    if (meta.isEmpty()) {
                        // Error
                        requestError = IfmapInvalidMetadata;
                        continue;
                    }
                    QDomNodeList ids = doc.elementsByTagName("identifier");
                    if (ids.isEmpty() || ids.length() > 2) {
                        // Error
                        requestError = IfmapInvalidIdentifier;
                        continue;
                    }

                    qDebug() << fnName << "number of identifiers:" << ids.length();
                    bool isLink = (ids.length() == 2) ? true : false;
                    Link key = keyFromNodeList(ids, isLink);
                    _mapGraph->addMeta(key, meta, isLink, publisherId);

                    // Determine if the update effects any subscriptions
                    markSubscriptionsForPolls(key, isLink);

                } else if (pubOperation.compare("delete", Qt::CaseInsensitive) == 0) {
                    QDomDocument doc("placeholder");
                    QDomElement el = pubItem->toDomElement(doc);
                    doc.appendChild(el);

                    QString filter = QString();
                    bool haveFilter = el.attributes().contains("filter");
                    if (haveFilter) {
                        filter = el.attributes().namedItem("filter").toAttr().value();
                        qDebug() << fnName << "delete filter:" << filter;
                    } else {
                        qDebug() << fnName << "no delete filter provided";
                    }

                    QDomNodeList ids = doc.elementsByTagName("identifier");
                    if (ids.isEmpty() || ids.length() > 2) {
                        // Error
                        requestError = IfmapInvalidIdentifier;
                        continue;
                    }

                    qDebug() << fnName << "number of identifiers:" << ids.length();
                    bool isLink = (ids.length() == 2) ? true : false;
                    Link key = keyFromNodeList(ids, isLink);

                    _mapGraph->deleteMetaWithFilter(key, isLink, haveFilter, filter);

                    // Determine if the delete effects any subscriptions
                    markSubscriptionsForPolls(key, isLink);

                } else {
                    // Error!
                    requestError = IfmapFailure;
                    qDebug() << fnName << "Client Error: Invalid publish sub-operation:" << pubOperation;
                    // TODO: This should result in a SOAP Fault!
                }
            }

            // Per IF-MAP1:3.8.1.3: IF-MAP the entire publish operation
            // MUST appear atomic to other clients.  So if multiple sub-operations, they need
            // to ALL be applied before any other search is allowed, or subscriptions matched.

            // At this point all the publishes have occurred, we can check subscriptions
            if (!requestError) {
                emit checkSubscriptionsForPolls();
            }
        }
        QtSoapType *pubMsgResponse = soapResponseForOperation(method, requestError);
        respMsg.addBodyItem(pubMsgResponse);

    } else if (method.compare("search", Qt::CaseInsensitive) == 0 && validSessId) {
        QtSoapStruct *searchResponse;

        QtSoapStruct &searchMeth = (QtSoapStruct&)reqMsg.method();
        QDomDocument doc("placeholder");
        QDomElement el = searchMeth.toDomElement(doc);
        doc.appendChild(el);

        QDomNodeList ids = doc.elementsByTagName("identifier");
        if (ids.isEmpty() || ids.length() > 1) {
            requestError = IfmapInvalidIdentifier;
            // TODO: Should send SOAP Client Fault
            searchResponse = (QtSoapStruct *)soapResponseForOperation(method, requestError);
        } else {
            bool isLink = false; // searches start on identifier not link
            Link key = keyFromNodeList(ids, isLink);
            Id startingId = key.first;

            QString matchLinks, resultFilter;
            int maxDepth, maxSize;
            bool searchParamError = searchParameters(searchMeth.attributes(), &maxDepth, &matchLinks, &maxSize, &resultFilter);

            if (!searchParamError) {
                QSet<Id> idList;
                QSet<Link > linkList;
                int currentDepth = -1;
                buildSearchGraph(startingId, matchLinks, maxDepth, currentDepth, &idList, &linkList);

                qDebug() << fnName << "Search Lists";
                qDebug() << fnName << "    idList size:" << idList.size();
                qDebug() << fnName << "    linkList size:" << linkList.size();

                searchResponse = (QtSoapStruct *)soapResponseForOperation(method, requestError);
                bool underMaxSize = addSearchResultsWithResultFilter(searchResponse, maxSize, resultFilter, idList, linkList);
                if (! underMaxSize) {
                    requestError = IfmapSearchResultsTooBig;
                    //TODO: Do I need to first delete existing searchResponse allocation?
                    searchResponse = (QtSoapStruct *)soapResponseForOperation(method, requestError);
                }

            } else {
                requestError = IfmapFailure;
                searchResponse = (QtSoapStruct *)soapResponseForOperation(method, requestError);
                // TODO: Should send SOAP Client Fault
            }
        }
        respMsg.addBodyItem(searchResponse);

    } else if (method.compare("subscribe", Qt::CaseInsensitive) == 0 && validSessId) {
        QtSoapType *subMsgResponse;

        qDebug() << fnName << "Will manage subscriptions for publisher:" << publisherId;
        QtSoapStruct &subMeth = (QtSoapStruct &)reqMsg.method();

        for (QtSoapStructIterator it(subMeth); it.current() && !requestError; ++it) {
            QtSoapStruct *subItem = (QtSoapStruct *)it.data();
            QString subOperation = subItem->name().name();
            qDebug() << fnName << "Subscribe operation:" << subOperation;
            if (subOperation.compare("update", Qt::CaseInsensitive) == 0) {

                QDomDocument doc("placeholder");
                QDomElement el = subItem->toDomElement(doc);
                doc.appendChild(el);

                QString subName;
                if (subItem->attributes().contains("name")) {
                    subName = subItem->attributes().namedItem("name").toAttr().value();
                    qDebug() << fnName << "Subscription name:" << subName;
                } else {
                    // Error
                    requestError = IfmapFailure;
                    qDebug() << fnName << "Client Error: Missing update subscription name";
                    // TODO: Should result in SOAP Client Fault
                }

                QDomNodeList ids = doc.elementsByTagName("identifier");
                if (ids.isEmpty() || ids.length() > 1) {
                    // Error
                    requestError = IfmapInvalidIdentifier;
                    qDebug() << fnName << "Client Error: Incorrect identifier in subscription";
                    // TODO: Should send SOAP Client Fault
                }

                if (!requestError) {
                    bool isLink = false; // searches start on identifier not link
                    Link key = keyFromNodeList(ids, isLink);
                    Id startingId = key.first;

                    QString matchLinks, resultFilter;
                    int maxDepth, maxSize;
                    // TODO: make this requestError = searchParameters(...)
                    bool subErrorParams = searchParameters(subItem->attributes(), &maxDepth, &matchLinks, &maxSize, &resultFilter);

                    if (!subErrorParams) {
                        // Only store one subscription list per client
                        QSet<Id> idList;
                        QSet<Link > linkList;
                        int currentDepth = -1;
                        buildSearchGraph(startingId, matchLinks, maxDepth, currentDepth, &idList, &linkList);

                        qDebug() << fnName << "Subscription:" << subName;
                        qDebug() << fnName << "    idList size:" << idList.size();
                        qDebug() << fnName << "    linkList size:" << linkList.size();

                        SearchGraph sub;
                        // All subs should be initially dirty, so they are checked
                        // when a client polls
                        sub.dirty = true;
                        sub.name = subName;
                        sub.startId = startingId;
                        sub.maxDepth = maxDepth;
                        sub.matchLinks = matchLinks;
                        sub.maxSize = maxSize;
                        sub.resultFilter = resultFilter;
                        sub.idList = idList;
                        sub.linkList = linkList;

                        QList<SearchGraph> subList = _subscriptionLists.value(publisherId);
                        if (subList.isEmpty()) {
                            subList << sub;
                        } else {
                            // Removal will fail if DNE - and that's ok
                            subList.removeOne(sub);
                            subList << sub;
                        }
                        qDebug() << fnName << "subList size:" << subList.size();

                        _subscriptionLists.insert(publisherId, subList);
                        qDebug() << fnName << "Adding SearchGraph to _subscriptionLists with name:" << subName;

                        // Per IF-MAP1:3.8.5: This subscription may result in a pollResult if
                        // this client has an active poll.
                        if (_activePolls.contains(publisherId)) {
                            // signal to check subscriptions for polls
                            emit checkSubscriptionsForPolls();
                        }
                    } else {
                        requestError = IfmapFailure;
                        // TODO: Should send SOAP Client Fault
                    }
                }
            } else if (subOperation.compare("delete", Qt::CaseInsensitive) == 0) {
                QString subName;
                if (subItem->attributes().contains("name")) {
                    subName = subItem->attributes().namedItem("name").toAttr().value();

                    SearchGraph delSub;
                    delSub.name = subName;

                    QList<SearchGraph> subList = _subscriptionLists.value(publisherId);
                    if (! subList.isEmpty()) {
                        subList.removeOne(delSub);
                        qDebug() << fnName << "Removing subscription from subList with name:" << subName;
                    } else {
                        qDebug() << fnName << "No subscriptions for publisher:" << publisherId;
                    }

                    if (! subList.isEmpty()) {
                        _subscriptionLists.insert(publisherId, subList);
                    } else {
                        _subscriptionLists.remove(publisherId);
                    }

                    qDebug() << fnName << "subList size:" << subList.size();
                } else {
                    // Error - no name in delete
                    requestError = IfmapFailure;
                    qDebug() << fnName << "Client Error: Missing delete subscription name";
                    // TODO: Should result in SOAP Client Fault
                }
            } else {
                // Error!
                requestError = IfmapFailure;
                qDebug() << fnName << "Client Error: Invalid subscription sub-operation:" << subOperation;
                // TODO: Should result in SOAP Client Fault
            }
        }
        subMsgResponse = soapResponseForOperation(method, requestError);

        respMsg.addBodyItem(subMsgResponse);

    } else if (method.compare("poll", Qt::CaseInsensitive) == 0 && validSessId) {
        QtSoapStruct *pollResult;

        if (_activeARCSessions.contains(publisherId)) {
            if (_subscriptionLists.value(publisherId).isEmpty()) {
                // No immediate client response
                respondNow = false;
                qDebug() << fnName << "No subscriptions for publisherId:" << publisherId;
            } else {
                pollResult = (QtSoapStruct *)soapResponseForOperation(method, requestError);

                int searchResultSize = pollResultsForPublisherId(pollResult, publisherId);
                qDebug() << fnName << "searchResultSize:" << searchResultSize;
                if (! searchResultSize) {
                    // No immediate client response
                    respondNow = false;
                } else {
                    respMsg.addBodyItem(pollResult);
                }
            }
        } else {
            // Error
            qDebug() << fnName << "No active ARC session for poll from publisherId:" << publisherId;
            requestError = IfmapInvalidSessionID;
            pollResult = (QtSoapStruct *)soapResponseForOperation(method, requestError);
            respMsg.addBodyItem(pollResult);
        }

    } else if (method.compare("purgePublisher", Qt::CaseInsensitive) == 0 && validSessId) {
        QString purgePubId;

        if (reqMsg.method().attributes().contains("publisher-id")) {
            purgePubId = reqMsg.method().attributes().namedItem("publisher-id").toAttr().value();
            qDebug() << fnName << "Got purgePublisher publisher-id:" << purgePubId;

            // Per IF-MAP1:3.8.6: A MAP Server MAY forbid deleting another client's metadata,
            // but must respond with an AccessDenied errorResult
            _mapGraph->deleteMetaWithPublisherId(purgePubId);

            // Check subscriptions for changes to Map Graph
            emit checkSubscriptionsForPolls();

        } else {
            // Error
            requestError = IfmapFailure;
            qDebug() << fnName << "Client Error: no publisher-id in purgePublisher method";
            // TODO: Should result in SOAP Client Fault
        }
        QtSoapType *purgePubResponse = soapResponseForOperation(method, requestError);
        respMsg.addBodyItem(purgePubResponse);

    } else {
        respMsg.setFaultCode(QtSoapMessage::Client);
        respMsg.setFaultString("Unrecognized SOAP Method");
    }

    if (respondNow) {
        QString sessId;
        // Per IF-MAP1:4.3: If the client specifies an invalid session-id,
        // the server MUST include that invalid session-id in the SOAP header
        // of its response and indicate an InvalidSessionID errorResult
        // in its reponse.
        if (! reqMsgSessId.isEmpty()) {
            sessId = reqMsgSessId;
        } else {
            sessId = _activeSSRCSessions.value(publisherId);
        }

        // Per IF-MAP1:4.3:A MAP Server MUST include session-id in SOAP Header
        QtSoapType *sessIdItem = new QtSoapSimpleType(QtSoapQName("session-id",IFMAP_NS_1),sessId);
        respMsg.addHeaderItem(sessIdItem);
        sendResponse(socket, respMsg);

        //socket->disconnectFromHost();
    } else {
        _activePolls.insert(publisherId, socket);
    }
}

bool Server::terminateARCSession(QString publisherId)
{
    const char *fnName = "Server::terminateARCSession:";
    bool hadExistingARCSession = false;

    if (_activeARCSessions.contains(publisherId)) {
        hadExistingARCSession = true;

        // End active ARC Session
        _activeARCSessions.remove(publisherId);
        qDebug() << fnName << "Ending active ARC Session for publisherId:" << publisherId;

        // Remove subscriptions
        if (_subscriptionLists.contains(publisherId)) {
            _subscriptionLists.remove(publisherId);
            qDebug() << fnName << "Removing subscriptions for publisherId:" << publisherId;
        }

        // Terminate polls
        if (_activePolls.contains(publisherId)) {
            QTcpSocket *pollSocket = _activePolls.value(publisherId);
            if (pollSocket->isValid()) {
                qDebug() << fnName << "Disconnecting socket from client:" << pollSocket;
                pollSocket->disconnectFromHost();
            }
            _activePolls.remove(publisherId);
            qDebug() << fnName << "Terminated active poll for publisherId:" << publisherId;
        }
    }

    return hadExistingARCSession;
}

bool Server::searchParameters(QDomNamedNodeMap searchAttrs, int *maxDepth, QString *matchLinks, int *maxSize, QString *resultFilter)
{
    const char *fnName = "Server::searchParameters:";

    // Return true on error!!!

    /* IF-MAP 1:3.8.2.7: If a MAP Client does not specify max-depth,
       the MAP Server MUST process the search with a max-depth of zero.
       If a MAP Client specifies a max-depth less than zero, the MAP
       Server MAY process the search with an unbounded max-depth.
    */
    if (searchAttrs.contains("max-depth")) {
        QString md = searchAttrs.namedItem("max-depth").toAttr().value();
        bool ok;
        *maxDepth = md.toInt(&ok);
        if (ok)
            qDebug() << fnName << "Got search parameter max-depth:" << *maxDepth;
        else
            return true;
    } else {
        *maxDepth = 0;
        qDebug() << fnName << "Using default search parameter max-depth:" << *maxDepth;
    }

    if (searchAttrs.contains("match-links")) {
        *matchLinks = searchAttrs.namedItem("match-links").toAttr().value();
        qDebug() << fnName << "Got search parameter match-links:" << *matchLinks;
    } else {
        *matchLinks = QString("*");
        qDebug() << fnName << "Using default search parameter match-links:" << matchLinks;
    }

    /* IF-MAP 1:3.8.2.7: MAP Servers MUST support size constraints up to
       and including 100KB 1 . If a MAP Client does not specify max-size,
       the MAP Server MUST process the search with a max-size of 100KB.
       If a MAP Client specifies a max-size of -1, the MAP Server MAY
       process the search with an unbounded max-size. If a MAP Client
       specifies a max-size that exceeds what the MAP Server can support,
       the MAP Server MUST enforce its own maximum size constraints.
    */
    if (searchAttrs.contains("max-size")) {
        QString ms = searchAttrs.namedItem("max-size").toAttr().value();
        bool ok;
        *maxSize = ms.toInt(&ok);
        if (ok)
            qDebug() << fnName << "Got search parameter max-size:" << *maxSize;
        else
            return true;
    } else {
        *maxSize = IFMAP_MAX_SIZE;
        qDebug() << fnName << "Using default search parameter max-size:" << *maxSize;
    }

    if (searchAttrs.contains("result-filter")) {
        *resultFilter = searchAttrs.namedItem("result-filter").toAttr().value();
        qDebug() << fnName << "Got search parameter result-filter:" << *resultFilter;
    } else {
        *resultFilter = QString("*");
        qDebug() << fnName << "Using default search parameter result-filter:" << resultFilter;
    }

    return false;
}

void Server::sendResponse(QTcpSocket *socket, const QtSoapMessage & respMsg)
{
    const char *fnName = "Server::sendResponse:";

    QByteArray respArr;
    respArr.append(respMsg.toXmlString(-1));

    QHttpResponseHeader header(200,"OK");
    header.setContentType("text/xml");
    //header.setValue("Content-Encoding","UTF-8");
    header.setContentLength( respArr.size() );

    if (socket->isValid()) {
        socket->write(header.toString().toUtf8() );
        socket->write( respArr );

        if (_debug.testFlag(Server::ShowHTTPHeaders))
            qDebug() << fnName << "Sent reply headers to client:" << endl << header.toString();

        if (_debug.testFlag(Server::ShowXML))
            qDebug() << fnName << "Sent reply to client:" << endl << respArr << endl;
    } else {
        qDebug() << fnName << "Socket is not valid!  Not sending reply to client";
    }
}

QtSoapType* Server::soapResponseForOperation(QString operation, bool operationError)
{
    QtSoapType *respMsg = 0;

    if (operation.compare("new-session", Qt::CaseInsensitive) == 0) {
        if (operationError) {
        } else {
        }
    } else if (operation.compare("attach-session", Qt::CaseInsensitive) == 0) {
        if (operationError) {
            respMsg = new QtSoapStruct(QtSoapQName("errorResult", IFMAP_NS_1));
            respMsg->setAttribute("errorCode","InvalidSessionId");
        } else {
        }
    } else if (operation.compare("publish", Qt::CaseInsensitive) == 0) {
        if (operationError) {
        } else {
            respMsg = new QtSoapSimpleType(QtSoapQName("publishReceived",IFMAP_NS_1));
        }
    } else if (operation.compare("search", Qt::CaseInsensitive) == 0) {
        if (operationError) {
        } else {
            respMsg = new QtSoapStruct(QtSoapQName("searchResult",IFMAP_NS_1));
        }
    } else if (operation.compare("subscribe", Qt::CaseInsensitive) == 0) {
        if (operationError) {
        } else {
            respMsg = new QtSoapSimpleType(QtSoapQName("subscribeReceived",IFMAP_NS_1));
        }
    } else if (operation.compare("poll", Qt::CaseInsensitive) == 0) {
        if (operationError) {
            respMsg = new QtSoapStruct(QtSoapQName("errorResult", IFMAP_NS_1));
            respMsg->setAttribute("errorCode","Failure");
            QtSoapSimpleType *eMsg = new QtSoapSimpleType(QtSoapQName("errorString"),
                                                               "ARC Session not attached");
            ((QtSoapStruct *)respMsg)->insert(eMsg);
        } else {
            respMsg = new QtSoapStruct(QtSoapQName("pollResult",IFMAP_NS_1));
        }
    } else if (operation.compare("purgePublisher", Qt::CaseInsensitive) == 0) {
        if (operationError) {
        } else {
            respMsg = new QtSoapSimpleType(QtSoapQName("purgePublishReceived",IFMAP_NS_1));
        }
    }

    return respMsg;
}

QtSoapStruct* Server::soapStructForId(Id id)
{
    QtSoapStruct *idOuterStruct = new QtSoapStruct(QtSoapQName("identifier"));

    QtSoapType *idStruct = 0;
    QtSoapSimpleType *device;
    switch(id.type()) {
        case Identifier::IdNone:
            break;
        case Identifier::AccessRequest:
            idStruct = new QtSoapSimpleType(QtSoapQName("access-request"));
            idStruct->setAttribute("name",id.value());
            break;
        case Identifier::DeviceAikName:
            idStruct = new QtSoapStruct(QtSoapQName("device"));
            device = new QtSoapSimpleType(QtSoapQName("aik-name"),id.value());
            ((QtSoapStruct *)idStruct)->insert(device);
            break;
        case Identifier::DeviceName:
            idStruct = new QtSoapStruct(QtSoapQName("device"));
            device = new QtSoapSimpleType(QtSoapQName("name"),id.value());
            ((QtSoapStruct *)idStruct)->insert(device);
            break;
        case Identifier::IpAddressIPv4:
            idStruct = new QtSoapSimpleType(QtSoapQName("ip-address"));
            idStruct->setAttribute("type","IPv4");
            idStruct->setAttribute("value", id.value());
            break;
        case Identifier::IpAddressIPv6:
            idStruct = new QtSoapSimpleType(QtSoapQName("ip-address"));
            idStruct->setAttribute("type","IPv6");
            idStruct->setAttribute("value", id.value());
            break;
        case Identifier::MacAddress:
            idStruct = new QtSoapSimpleType(QtSoapQName("mac-address"));
            idStruct->setAttribute("value", id.value());
            break;
        case Identifier::IdentityAikName:
            idStruct = new QtSoapSimpleType(QtSoapQName("identity"));
            idStruct->setAttribute("name", id.value());
            idStruct->setAttribute("type", "aik-name");
            break;
        case Identifier::IdentityDistinguishedName:
            idStruct = new QtSoapSimpleType(QtSoapQName("identity"));
            idStruct->setAttribute("name", id.value());
            idStruct->setAttribute("type", "distinguished-name");
            break;
        case Identifier::IdentityDnsName:
            idStruct = new QtSoapSimpleType(QtSoapQName("identity"));
            idStruct->setAttribute("name", id.value());
            idStruct->setAttribute("type", "dns-name");
            break;
        case Identifier::IdentityEmailAddress:
            idStruct = new QtSoapSimpleType(QtSoapQName("identity"));
            idStruct->setAttribute("name", id.value());
            idStruct->setAttribute("type", "email-address");
            break;
        case Identifier::IdentityKerberosPrincipal:
            idStruct = new QtSoapSimpleType(QtSoapQName("identity"));
            idStruct->setAttribute("name", id.value());
            idStruct->setAttribute("type", "kerberos-principal");
            break;
        case Identifier::IdentityTrustedPlatformModule:
            idStruct = new QtSoapSimpleType(QtSoapQName("identity"));
            idStruct->setAttribute("name", id.value());
            idStruct->setAttribute("type", "trusted-platform-module");
            break;
        case Identifier::IdentityUsername:
            idStruct = new QtSoapSimpleType(QtSoapQName("identity"));
            idStruct->setAttribute("name", id.value());
            idStruct->setAttribute("type", "username");
            break;
        case Identifier::IdentitySipUri:
            idStruct = new QtSoapSimpleType(QtSoapQName("identity"));
            idStruct->setAttribute("name", id.value());
            idStruct->setAttribute("type", "sip-uri");
            break;
        case Identifier::IdentityHipHit:
            idStruct = new QtSoapSimpleType(QtSoapQName("identity"));
            idStruct->setAttribute("name", id.value());
            idStruct->setAttribute("type", "hip-hit");
            break;
        case Identifier::IdentityTelUri:
            idStruct = new QtSoapSimpleType(QtSoapQName("identity"));
            idStruct->setAttribute("name", id.value());
            idStruct->setAttribute("type", "tel-uri");
            break;
        case Identifier::IdentityOther:
            idStruct = new QtSoapSimpleType(QtSoapQName("identity"));
            idStruct->setAttribute("name", id.value());
            idStruct->setAttribute("type", "other");
            idStruct->setAttribute("other-type-definition", id.other());
            break;
    }

    if ( id.type() != Identifier::DeviceAikName && id.type() != Identifier::DeviceName
         && !(id.ad().isEmpty()) ) {
        idStruct->setAttribute("administrative-domain", id.ad());
    }

    idOuterStruct->insert(idStruct);

    return idOuterStruct;
}

bool Server::addSearchResultsWithResultFilter(QtSoapStruct *soapResponse, int maxSize, QString resultFilter, QSet<Id> idList, QSet<Link> linkList)
{
    const char *fnName = "Server::addSearchResultsWithResultFilter:";

    // TODO: Do a running check on curSize and
    // return false if we exceed maxSize
    int curSize = 0;
    if (curSize > maxSize) return false;

    qDebug() << fnName << "linkList size:" << linkList.size();
    QSetIterator<Link> linkIt(linkList);
    while (linkIt.hasNext()) {
        Link link = linkIt.next();
        QList<Meta> linkMetaList = _mapGraph->metaForLink(link);
        qDebug() << fnName << "linkMetaList size for link:" << link << "-->" << linkMetaList.size();
        if (!linkMetaList.isEmpty()) {
            QtSoapStruct *linkResult = new QtSoapStruct(QtSoapQName("linkResult"));
            QtSoapStruct *idStruct1 = soapStructForId(link.first);
            QtSoapStruct *idStruct2 = soapStructForId(link.second);

            QtSoapStruct *metaResult = 0;
            bool gotOne = false;
            QListIterator<Meta> metaIt(linkMetaList);
            while (metaIt.hasNext()) {
                Meta linkMeta = metaIt.next();
                QList<QDomNode> metaNodes = linkMeta.metaDomNodes();
                qDebug() << fnName << "metaNodes size:" << metaNodes.size();
                QListIterator<QDomNode> nodeIt(metaNodes);
                while (nodeIt.hasNext()) {
                    QDomNode metaNode = nodeIt.next();
                    bool metaPassesFilter = true;
                    //TODO: Implement and apply resultFilter
                    if (metaPassesFilter) {
                        if (!gotOne) {
                            metaResult = new QtSoapStruct(QtSoapQName("metadata"));
                            gotOne = true;
                        }
                        if (metaNode.firstChild().isElement()) {
                            QtSoapStruct *metaResultEntry = new QtSoapStruct();
                            metaResultEntry->parse(metaNode);
                            metaResult->insert(metaResultEntry);
                        } else {
                            QtSoapSimpleType *metaResultEntry = new QtSoapSimpleType();
                            metaResultEntry->parse(metaNode);
                            metaResult->insert(metaResultEntry);
                        }
                    } else {
                        qDebug() << fnName << "Metadata with name:" << linkMeta.elementName()
                                 << "does not pass resultFilter:" << resultFilter;
                    }
                }
            }

            if (gotOne) {
                linkResult->insert(metaResult);
            }
            linkResult->insert(idStruct2);
            linkResult->insert(idStruct1);
            soapResponse->insert(linkResult);
        }
    }

    QSetIterator<Id> idIt(idList);
    while (idIt.hasNext()) {
        Id id = idIt.next();
        QList<Meta> idMetaList = _mapGraph->metaForId(id);
        if (!idMetaList.isEmpty()) {
            QtSoapStruct *idResult = new QtSoapStruct(QtSoapQName("identifierResult"));
            QtSoapStruct *idStruct = soapStructForId(id);

            QtSoapStruct *metaResult = 0;
            bool gotOne = false;
            QListIterator<Meta> metaIt(idMetaList);
            while (metaIt.hasNext()) {
                Meta idMeta = metaIt.next();
                QList<QDomNode> metaNodes = idMeta.metaDomNodes();
                QListIterator<QDomNode> nodeIt(metaNodes);
                while (nodeIt.hasNext()) {
                    QDomNode metaNode = nodeIt.next();
                    bool metaPassesFilter = true;
                    //TODO: Implement and apply resultFilter
                    if (metaPassesFilter) {
                        if (!gotOne) {
                            metaResult = new QtSoapStruct(QtSoapQName("metadata"));
                            gotOne = true;
                        }
                        if (metaNode.firstChild().isElement()) {
                            QtSoapStruct *metaResultEntry = new QtSoapStruct();
                            metaResultEntry->parse(metaNode);
                            metaResult->insert(metaResultEntry);
                        } else {
                            QtSoapSimpleType *metaResultEntry = new QtSoapSimpleType();
                            metaResultEntry->parse(metaNode);
                            metaResult->insert(metaResultEntry);
                        }
                    } else {
                        qDebug() << fnName << "Metadata with name:" << idMeta.elementName()
                                 << "does not pass resultFilter:" << resultFilter;
                    }
                }
            }

            if (gotOne) {
                idResult->insert(metaResult);
            }
            idResult->insert(idStruct);
            soapResponse->insert(idResult);
        }
    }

    return true;
}

void Server::buildSearchGraph(Id startId, QString matchLinks, int maxDepth,
                    int currentDepth, // Pass by value!  Must initially be -1.
                    QSet<Id> *idList,
                    QSet<Link > *linkList)
{
    const char *fnName = "Server::buildSearchGraph";

    /* IF-MAP1:3.8.2.7: Recursive Algorithm is from spec */
    // 1. Current id, current results, current depth
    currentDepth++;
    qDebug() << fnName << "Starting identifier:" << startId;
    qDebug() << fnName << "Current depth:" << currentDepth;

    // 2. Check max depth reached
    if (currentDepth >= maxDepth) {
        qDebug() << fnName << "max depth reached:" << maxDepth;
        return;
    }

    // 3/4. Save current identifier in list of traversed identifiers
    // so we can later gather metadata from these identifiers.
    idList->insert(startId);

    // 5. Get list of links that have startId in link and pass matchLinks filter
    QSet<Link > linksWithCurId = _mapGraph->matchLinksAtId(startId, matchLinks);

    // Remove links we've already seen before
    linksWithCurId.subtract(*linkList);

    if (linksWithCurId.isEmpty()) {
        qDebug() << fnName << "linksWithCurId is empty!!!";
        return;
    } else {
        // 6. Append subLinkList to linkList (unite removes repeats)
        linkList->unite(linksWithCurId);

        // 7. Recurse
        QSetIterator<Link > linkIter(linksWithCurId);
        while (linkIter.hasNext()) {
            Link link = linkIter.next();
            Id linkedId = otherIdForLink(link, startId);
            // linkedId becomes startId in recursion
            buildSearchGraph(linkedId, matchLinks, maxDepth, currentDepth, idList, linkList);
        }
    }


}

Id Server::otherIdForLink(Link link, Id targetId)
{
    if (link.first == targetId)
        return link.second;
    else
        return link.first;
}

// Iterate over all subscriptions for all publishers, checking and/or rebuilding
// the SearchGraphs.  If a subscription results in a changed SearchGraph,
// mark the subscription as dirty, so that we can send out pollResults.
void Server::markSubscriptionsForPolls(Link link, bool isLink)
{
    const char *fnName = "Server::markSubscriptionsForPolls:";

    // An existing subscription becomes dirty in 3 cases:
    // 1. metadata is added to or removed from an identifier already in the SearchGraph
    //    --> In this case, we don't need to rebuild the SearchGraph
    // 2. metadata is added to or removed from a link already in the SearchGraph
    //    --> In this case, we don't need to rebuild the SearchGraph
    // 3. metadata is added to or removed from a link which has one identifier
    //    already in the SearchGraph
    //    --> In this case we need to rebuild the SearchGraph, especially because this
    //        new link could link two separate sub-graphs together.

    QMutableHashIterator<QString,QList<SearchGraph> > allSubsIt(_subscriptionLists);
    while (allSubsIt.hasNext()) {
        allSubsIt.next();
        QString pubId = allSubsIt.key();
        QList<SearchGraph> subList = allSubsIt.value();
        qDebug() << fnName << "publisher:" << pubId << "has num subscriptions:" << subList.size();

        bool pubHasDirtySub = false;
        QMutableListIterator<SearchGraph> subIt(subList);
        while (subIt.hasNext()) {
            SearchGraph sub = subIt.next();
            qDebug() << fnName << "  checking subscription named:" << sub.name;

            bool isDirty = false;

            if (! isLink) {
                // Case 1.
                if (sub.idList.contains(link.first)) {
                    isDirty = true;
                    qDebug() << fnName << "   subscription is dirty with id:" << link.first;
                }
            } else {
                if (sub.linkList.contains(link)) {
                    // Case 2.
                    isDirty = true;
                    qDebug() << fnName << "   subscription is dirty with link:" << link;
                } else {
                    // Case 3.
                    QSet<Id> idList;
                    QSet<Link > linkList;
                    int currentDepth = -1;
                    buildSearchGraph(sub.startId, sub.matchLinks, sub.maxDepth, currentDepth, &idList, &linkList);

                    if (sub.idList != idList) {
                        isDirty = true;
                        sub.idList = idList;
                        qDebug() << fnName << "   subscription is dirty with changed idList, size:" << idList.size();
                    }

                    if (sub.linkList != linkList) {
                        isDirty = true;
                        sub.linkList = linkList;
                        qDebug() << fnName << "   subscription is dirty with changed linkList, size:" << linkList.size();
                    }
                }
            }

            if (isDirty) {
                sub.dirty = true;
                subIt.setValue(sub);
                pubHasDirtySub = true;
            }
        }

        if (pubHasDirtySub) {
            allSubsIt.setValue(subList);
        }
    }
}

Link Server::keyFromNodeList(QDomNodeList ids, bool isLink)
{
    Link key;
    QString idString;
    QTextStream idStream(&idString);

    if (! isLink) {
        Id id = idFromNode(ids.at(0).firstChild());
        key.first = id;
    } else {
        Id id1 = idFromNode(ids.at(0).firstChild());
        Id id2 = idFromNode(ids.at(1).firstChild());
        key = Identifier::makeLinkFromIds(id1, id2);
    }

    return key;
}

// TODO: add parameter to return IFMAP_ERRORCODES_1, e.g. IfmapInvalidIdentifier
Id Server::idFromNode(QDomNode idNode)
{
    const char *fnName = "Server::idFromNode:";

    QDomNamedNodeMap attrs = idNode.attributes();
    bool parseError = false;
    Identifier::IdType idType = Identifier::IdNone;

    QString ad = attrs.contains("administrative-domain") ?
                 attrs.namedItem("administrative-domain").toAttr().value() :
                 QString();

    QString value;
    QString other; // This is only for type Identifier::IdentityOther

    // TODO: Do some rudimentary type checking on the value, e.g.
    // (QHostAddress::setAddress ( const QString & address )) == true
    QString idName = idNode.toElement().tagName();
    if (idName.compare("access-request", Qt::CaseInsensitive) == 0) {
        idType = Identifier::AccessRequest;

        if (attrs.contains("name")) {
            idType = Identifier::AccessRequest;
            value = attrs.namedItem("name").toAttr().value();
            qDebug() << fnName << "Got access-request name:" << value;
        } else {
            // Error - did not specify access-request name
            parseError = true;
        }
    } else if (idName.compare("device", Qt::CaseInsensitive) == 0) {
        QString deviceType = idNode.firstChildElement().tagName();
        if (deviceType.compare("aik-name", Qt::CaseInsensitive) == 0) {
            idType = Identifier::DeviceAikName;
            value = idNode.firstChildElement().text();
            qDebug() << fnName << "Got device aik-name:" << value;
        } else if (deviceType.compare("name", Qt::CaseInsensitive) == 0) {
            idType = Identifier::DeviceName;
            value = idNode.firstChildElement().text();
            qDebug() << fnName << "Got device name:" << value;
        } else {
            // Error - unknown device type
            parseError = true;
        }
    } else if (idName.compare("identity", Qt::CaseInsensitive) == 0) {
        QString type;
        if (attrs.contains("type")) {
            type = attrs.namedItem("type").toAttr().value();
            if (type.compare("aik-name", Qt::CaseInsensitive) == 0) {
                idType = Identifier::IdentityAikName;
            } else if (type.compare("distinguished-name", Qt::CaseInsensitive) == 0) {
                idType = Identifier::IdentityDistinguishedName;
            } else if (type.compare("dns-name", Qt::CaseInsensitive) == 0) {
                idType = Identifier::IdentityDnsName;
            } else if (type.contains("email-address", Qt::CaseInsensitive) == 0) {
                idType = Identifier::IdentityEmailAddress;
            } else if (type.compare("kerberos-principal", Qt::CaseInsensitive) == 0) {
                idType = Identifier::IdentityKerberosPrincipal;
            } else if (type.compare("trusted-platform-module", Qt::CaseInsensitive) == 0) {
                idType = Identifier::IdentityTrustedPlatformModule;
            } else if (type.compare("username", Qt::CaseInsensitive) == 0) {
                idType = Identifier::IdentityUsername;
            } else if (type.compare("sip-uri", Qt::CaseInsensitive) == 0) {
                idType = Identifier::IdentitySipUri;
            } else if (type.compare("hip-hit", Qt::CaseInsensitive) == 0) {
                idType = Identifier::IdentityHipHit;
            } else if (type.compare("tel-uri", Qt::CaseInsensitive) == 0) {
                idType = Identifier::IdentityTelUri;
            } else if (type.compare("other", Qt::CaseInsensitive) == 0) {
                idType = Identifier::IdentityOther;
            } else {
                // Error - unknown identity type
                parseError = true;
            }
        } else {
            // Error - did not specify identity type
            parseError = true;
        }

        if (attrs.contains("name")) {
            value = attrs.namedItem("name").toAttr().value();
            qDebug() << fnName << "Got identity name:" << value;
        } else {
            // Error - did not specify identity name attribute
            parseError = true;
        }

        if (idType == Identifier::IdentityOther) {
            if (attrs.contains("other-type-definition")) {
                // Append other-type-definition to value
                other = attrs.namedItem("other-type-definition").toAttr().value();
                qDebug() << fnName << "Got identity other-type-def:" << other;
            } else {
                // Error - MUST have other-type-definition if idType is IdentityOther
                parseError = true;
            }
        }
    } else if (idName.compare("ip-address", Qt::CaseInsensitive) == 0) {
        QString type;
        if (attrs.contains("type")) {
            type = attrs.namedItem("type").toAttr().value();
            if (type.compare("IPv4", Qt::CaseInsensitive) == 0) {
                idType = Identifier::IpAddressIPv4;
            } else if (type.compare("IPv6", Qt::CaseInsensitive) == 0) {
                idType = Identifier::IpAddressIPv6;
            } else {
                // Error - did not correctly specify type
                parseError = true;
            }
        } else {
            idType = Identifier::IpAddressIPv4;
        }

        if (attrs.contains("value")) {
            value = attrs.namedItem("value").toAttr().value();
            qDebug() << fnName << "Got ip-address:" << value;
        } else {
            // Error - did not specify ip-address value attribute
            parseError = true;
        }

    } else if (idName.compare("mac-address", Qt::CaseInsensitive) == 0) {
        idType = Identifier::MacAddress;

        if (attrs.contains("value")) {
            value = attrs.namedItem("value").toAttr().value();
            qDebug() << fnName << "Got mac-address:" << value;
        } else {
            // Error - did not specify mac-address value attribute
            parseError = true;
        }
    } else {
        // Error - unknown identifier name
        parseError = true;
    }

    Id id;
    if (!parseError) {
        id.setType(idType);
        id.setAd(ad);
        id.setValue(value);
        id.setOther(other);
    } else {
        qDebug() << fnName << "Error parsing identifier";
    }
    return id;
}

void Server::buildPollResults()
{
    const char *fnName = "Server::buildPollResults:";
    QHashIterator<QString,QList<SearchGraph> > allSubsIt(_subscriptionLists);
    while (allSubsIt.hasNext()) {
        allSubsIt.next();
        QString pubId = allSubsIt.key();

        // Check if publisher has active poll
        if (_activePolls.contains(pubId)) {
            qDebug() << fnName << "Building poll results for publisher with active poll:" << pubId;
            QtSoapStruct *pollResult = (QtSoapStruct *)soapResponseForOperation("poll", false);

            int searchResultSize = pollResultsForPublisherId(pollResult, pubId);
            if (searchResultSize) {
                QtSoapMessage respMsg;
                QString sessId = _activeARCSessions.value(pubId);
                QtSoapType *sessIdItem = new QtSoapSimpleType(QtSoapQName("session-id",IFMAP_NS_1),sessId);
                respMsg.addHeaderItem(sessIdItem);
                respMsg.addBodyItem(pollResult);

                // Send it off
                sendResponse(_activePolls.value(pubId), respMsg);
            }

        }
    }
}

int Server::pollResultsForPublisherId(QtSoapStruct *pollResult, QString publisherId)
{
    const char *fnName = "Server::pollResultsForPublisherId:";
    int maxSearchResultSize = 0;
    bool haveDirtySub = false;

    QList<SearchGraph> subList = _subscriptionLists.value(publisherId);
    QMutableListIterator<SearchGraph> subIt(subList);
    while (subIt.hasNext()) {
        SearchGraph sub = subIt.next();

        qDebug() << fnName << "Subscription named:" << sub.name << "is dirty:" << sub.dirty;
        if (sub.dirty) {
            QtSoapStruct *searchResult = new QtSoapStruct(QtSoapQName("searchResult"));
            searchResult->setAttribute("name",sub.name);
            bool underMaxSize = addSearchResultsWithResultFilter(searchResult, sub.maxSize, sub.resultFilter, sub.idList, sub.linkList);
            //TODO: handle case of underMaxSize==false, i.e. results too big
            if (! underMaxSize) {
            }
            pollResult->insert(searchResult);

            int srSize = searchResult->count();
            qDebug() << fnName << "srSize:" << srSize;
            if (srSize > maxSearchResultSize) maxSearchResultSize = srSize;
            // Reset dirty flag
            haveDirtySub = true;
            sub.dirty = false;
            subIt.setValue(sub);
        }
    }

    if (haveDirtySub) {
        _subscriptionLists.insert(publisherId, subList);
    }

    return maxSearchResultSize;
}
