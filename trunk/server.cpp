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
#include <QXmlQuery>

#include "server.h"

Server::Server(MapGraph *mapGraph, quint16 port, QObject *parent)
        : QTcpServer(parent), _mapGraph(mapGraph)
{
    const char *fnName = "Server::Server:";

    // TODO: Add SSL

    _debug = Server::DebugNone;
    _nonStdBehavior = Server::DisableNonStdBehavior;
    _mapVersionSupport = Server::SupportIfmapV11;

    bool listening = listen(QHostAddress::Any, port);
    if (!listening) {
        qDebug() << fnName << "Server will not listen on port:" << port;
    } else {
        this->setMaxPendingConnections(30); // 30 is QTcpServer default

        connect(this, SIGNAL(newConnection()), this, SLOT(newClientConnection()));
        connect(this, SIGNAL(headerReceived(QTcpSocket*,QNetworkRequest)),
                this, SLOT(processHeader(QTcpSocket*,QNetworkRequest)));

        connect(this, SIGNAL(requestMessageReceived(QTcpSocket*,QtSoapMessage)),
                this, SLOT(processRequest(QTcpSocket*,QtSoapMessage)));

        connect(this, SIGNAL(checkActivePolls()),
                this, SLOT(sendResultsOnActivePolls()));

        // Seed RNG for session-ids
        qsrand(QDateTime::currentDateTime().toTime_t());

        // Register IF-MAP Namespaces
        QtSoapNamespaces &registry = QtSoapNamespaces::instance();
        if (_mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
            registry.registerNamespace("ifmap", IFMAP_NS_1);
            registry.registerNamespace("meta", IFMAP_META_NS_1);
        }
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
            // TODO: Set a max on the size of the requestByteArr
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

    // TODO: Improve reading of SOAP requests spanning multiple calls to this method
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
    QNetworkRequest requestWithHdr;
    bool end = false;
    QString tmp;
    QString headerStr = QLatin1String("");

    while (!end && socket->canReadLine()) {
        tmp = QString::fromUtf8(socket->readLine());
        if (tmp == QLatin1String("\r\n") || tmp == QLatin1String("\n") || tmp.isEmpty()) {
            end = true;
        } else {
            int hdrSepIndex = tmp.indexOf(":");
            if (hdrSepIndex != -1) {
                QString hdrName = tmp.left(hdrSepIndex);
                QString hdrValue = tmp.mid(hdrSepIndex+1).trimmed();
                requestWithHdr.setRawHeader(hdrName.toUtf8(), hdrValue.toUtf8());
                //qDebug() << fnName << "Got header:" << hdrName << "--->" << hdrValue;
            }
            headerStr += tmp;
        }
    }

    if (end) {
        emit headerReceived(socket, requestWithHdr);
    }

    if (_debug.testFlag(Server::ShowHTTPHeaders))
        qDebug() << fnName << "headerStr:" << endl << headerStr;

    return headerStr.length();
}

void Server::processHeader(QTcpSocket *socket, QNetworkRequest requestHdrs)
{
    const char *fnName = "Server::processHeader:";

    // TODO: Improve http protocol support
    if (requestHdrs.hasRawHeader(QByteArray("Expect"))) {
        if (_debug.testFlag(Server::ShowHTTPHeaders))
            qDebug() << fnName << "Got Expect header";
        QByteArray expectValue = requestHdrs.rawHeader(QByteArray("Expect"));
        if (! expectValue.isEmpty() && expectValue.contains(QByteArray("100-continue"))) {
            if (_debug.testFlag(Server::ShowHTTPHeaders)) {
                qDebug() << fnName << "Got 100-continue Expect Header";
            }
            sendHttpResponse(socket, 100, "Continue");
        }
    }

}

void Server::sendHttpResponse(QTcpSocket *socket, int hdrNumber, QString hdrText)
{
    const char *fnName = "Server::sendHttpResponse:";

    if (_debug.testFlag(Server::ShowHTTPHeaders)) {
        qDebug() << fnName << "Sending Http Response:" << hdrNumber << hdrText;
    }

    QHttpResponseHeader header(hdrNumber, hdrText);
    if (socket->state() == QAbstractSocket::ConnectedState) {
        socket->write(header.toString().toUtf8() );
    }
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
    if (_mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
        header.setValue("Server","omapd/ifmap1.1");
    }

    if (socket->state() == QAbstractSocket::ConnectedState) {
        socket->write(header.toString().toUtf8() );
        socket->write( respArr );

        if (_debug.testFlag(Server::ShowHTTPHeaders))
            qDebug() << fnName << "Sent reply headers to client:" << endl << header.toString();

        if (_debug.testFlag(Server::ShowXML))
            qDebug() << fnName << "Sent reply to client:" << endl << respArr << endl;
    } else {
        qDebug() << fnName << "Socket is not connected!  Not sending reply to client";
    }
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

    // TODO: Set a timer to delete session metadata

    socket->deleteLater();
}

QString Server::computePubId(QTcpSocket *socket, QString appId)
{
    // TODO: Make publisherId depend on peer identity, not IP address
    QString publisherId = socket->peerAddress().toString();

    if (! appId.isEmpty()) {
        publisherId += ":";
        publisherId += appId;
    }

    return publisherId;
}

IFMAP_ERRORCODES_1 Server::validateSessionId(QtSoapMessage msg, QTcpSocket *socket, QString* sessionId)
{
    const char *fnName = "Server::validateSessionId:";

    IFMAP_ERRORCODES_1 error = ::ErrorNone;

    if (_mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
        QtSoapStruct soapHdr = msg.header();
        QtSoapSimpleType sessIdElement = (QtSoapSimpleType &)soapHdr.at(QtSoapQName("session-id",IFMAP_NS_1));
        *sessionId = sessIdElement.value().toString();
        if (_debug.testFlag(Server::ShowClientOps)) {
            qDebug() << fnName << "Got session-id in IF-MAP 1.1 client request:" << *sessionId;
        }
    }

    if (! (*sessionId).isEmpty()) {
        if (_debug.testFlag(Server::ShowClientOps)) {
            qDebug() << fnName << "Using session-id in client request:" << *sessionId;
        }
    } else if (_nonStdBehavior.testFlag(Server::IgnoreSessionId)) {
        // NON-STANDARD BEHAVIOR!!!
        // This let's someone curl in a bunch of messages without worrying about
        // maintaining SSRC state.

        // NOTE: It is not possible to use curl and combine Server::IgnoreSessionId
        // and Server::EnablePubIdHint because of the lack of the pubIdHint in subsequent
        // messages after newSession.

        qDebug() << fnName << "NON-STANDARD: Ignoring invalid or missing session-id";
        QString publisherId = computePubId(socket);
        if (_activeSSRCSessions.contains(publisherId)) {
            *sessionId = _activeSSRCSessions.value(publisherId);
        }
    }

    // Do we have a corresponding publisherId for this session-id?
    QString publisherId = _activeSSRCSessions.key(*sessionId);
    if (! publisherId.isEmpty()) {
        // We do have an active SSRC session
        if (_debug.testFlag(Server::ShowClientOps)) {
            qDebug() << fnName << "Got session-id:" << *sessionId
                     << "and publisherId:" << publisherId;
        }
    } else {
        // We do NOT have a valid SSRC session
        error = ::IfmapInvalidSessionID;
    }

    return error;
}

void Server::processRequest(QTcpSocket *socket, QtSoapMessage reqMsg)
{
    const char *fnName = "Server::processRequest:";
    bool namespaceError = false;

    if (_debug.testFlag(Server::ShowClientOps)) qDebug() << endl << fnName << "Socket:" << socket;

    QtSoapQName arg = reqMsg.method().name();
    QString method = arg.name();
    QString ns = arg.uri();
    if (_debug.testFlag(Server::ShowClientOps)) {
        qDebug() << fnName << "Received method call:" << method;
        qDebug() << fnName << "Received method namespace:" << ns;
    }

    QString newSessMN, attachSessMN;

    if (_mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
        newSessMN = "new-session";
        attachSessMN = "attach-session";
        if (ns.compare(IFMAP_NS_1) != 0) {
            namespaceError = true;
        }
    }

    if (namespaceError) {
        QtSoapMessage respMsg;
        respMsg.setFaultCode(QtSoapMessage::Client);
        respMsg.setFaultString("Invalid IF-MAP Schema Version");
        sendResponse(socket, respMsg);
    } else if (method.compare(newSessMN) == 0) {
        processNewSession(socket, reqMsg);
    } else if (method.compare(attachSessMN) == 0) {
        processAttachSession(socket, reqMsg);
    } else if (method.compare("publish") == 0) {
        processPublish(socket, reqMsg);
    } else if (method.compare("subscribe") == 0) {
        processSubscribe(socket, reqMsg);
    } else if (method.compare("search") == 0) {
        processSearch(socket, reqMsg);
    } else if (method.compare("purgePublisher") == 0) {
        processPurgePublisher(socket, reqMsg);
    } else if (method.compare("poll") == 0) {
        processPoll(socket, reqMsg);
    } else {
        QtSoapMessage respMsg;
        respMsg.setFaultCode(QtSoapMessage::Client);
        respMsg.setFaultString("Unrecognized SOAP Method");
        sendResponse(socket, respMsg);
    }

    return;
}

void Server::processNewSession(QTcpSocket *socket, QtSoapMessage reqMsg)
{
    const char *fnName = "Server::processNewSession:";

    // NON-STANDARD BEHAVIOR!!!
    // SPEC: A publisherId hint from the client might be a nice addition to the spec
    //       and could be a unique id the client believes it has.  The server of
    //       course can override the hint.  But this would help a lot when
    //       it is impossible to otherwise distinguish client identities.
    //       However, this would make it possible for a client to publish metadata
    //       in the guise of a different client.
    //       If used, the "pubIdHint" attribute is only included in the newSession method.
    QString pubIdHint;
    if (_nonStdBehavior.testFlag(Server::EnablePubIdHint) &&
        reqMsg.method().attributes().contains("pubIdHint")) {
        pubIdHint = reqMsg.method().attributes().namedItem("pubIdHint").toAttr().value();
        qDebug() << fnName << "Got pubIdHint:" << pubIdHint;
        qDebug() << fnName << "NON-STANDARD: Using pubIdHint attribute in newSession";
    }

    QString publisherId = computePubId(socket, pubIdHint);

    QString sessId;
    // Check if we have an SSRC session already for this publisherId
    if (_activeSSRCSessions.contains(publisherId)) {
        sessId = _activeSSRCSessions.value(publisherId);
        terminateSession(sessId);
    } else {
        QString sid;
        sid.setNum(qrand());
        QByteArray sidhash = QCryptographicHash::hash(sid.toAscii(), QCryptographicHash::Md5);
        sessId = QString(sidhash.toHex());
    }
    _activeSSRCSessions.insert(publisherId, sessId);

    QtSoapMessage respMsg;
    if (_mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
        QtSoapType *sessIdItem = new QtSoapSimpleType(QtSoapQName("session-id",IFMAP_NS_1),sessId);
        respMsg.addBodyItem(sessIdItem);
        QtSoapType *pubIdItem = new QtSoapSimpleType(QtSoapQName("publisher-id",IFMAP_NS_1),publisherId);
        respMsg.addBodyItem(pubIdItem);
        QtSoapType *sessIdHdrItem = new QtSoapSimpleType(QtSoapQName("session-id",IFMAP_NS_1),sessId);
        QtSoapType *pubIdHdrItem = new QtSoapSimpleType(QtSoapQName("publisher-id",IFMAP_NS_1),publisherId);
        respMsg.addHeaderItem(sessIdHdrItem);
        respMsg.addHeaderItem(pubIdHdrItem);
    }
    sendResponse(socket, respMsg);
}

void Server::processAttachSession(QTcpSocket *socket, QtSoapMessage reqMsg)
{
    const char *fnName = "Server::processAttachSession:";
    QtSoapMessage respMsg;

    QString attachSessMN;
    if (_mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
        attachSessMN = "attach-session";
    }

    QString sessId;
    IFMAP_ERRORCODES_1 requestError = validateSessionId(reqMsg, socket, &sessId);
    QString publisherId = _activeSSRCSessions.key(sessId);

    if (!requestError) {
        // Terminate any existing ARC sessions
        if (terminateARCSession(sessId)) {
            // If we had an existing ARC session, end the session
            terminateSession(sessId);
            requestError = ::IfmapInvalidSessionID;
            qDebug() << fnName << "Already have existing ARC session, terminating";
            respMsg = soapResponseMsg(soapResponseForOperation(attachSessMN, requestError));
        } else {
            if (_debug.testFlag(Server::ShowClientOps)) {
                qDebug() << fnName << "Adding ARC session for publisher:" << publisherId;
            }
            _activeARCSessions.insert(publisherId, sessId);

            if (_mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
                QtSoapType *sessIdItem = new QtSoapSimpleType(QtSoapQName("session-id",IFMAP_NS_1),sessId);
                respMsg.addBodyItem(sessIdItem);
                QtSoapType *pubIdItem = new QtSoapSimpleType(QtSoapQName("publisher-id",IFMAP_NS_1),publisherId);
                respMsg.addBodyItem(pubIdItem);
            }
        }
    } else {
        respMsg = soapResponseMsg(soapResponseForOperation(attachSessMN, requestError));
    }

    if (_mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
        QtSoapType *sessIdHdrItem = new QtSoapSimpleType(QtSoapQName("session-id",IFMAP_NS_1),sessId);
        respMsg.addHeaderItem(sessIdHdrItem);
        QtSoapType *pubIdHdrItem = new QtSoapSimpleType(QtSoapQName("publisher-id",IFMAP_NS_1),publisherId);
        respMsg.addHeaderItem(pubIdHdrItem);
    }
    sendResponse(socket, respMsg);

}

void Server::processPublish(QTcpSocket *socket, QtSoapMessage reqMsg)
{
    const char *fnName = "Server::processPublish:";

    QString sessId;
    IFMAP_ERRORCODES_1 requestError = validateSessionId(reqMsg, socket, &sessId);
    QString publisherId = _activeSSRCSessions.key(sessId);

    QtSoapStruct &pubMeth = (QtSoapStruct &)reqMsg.method();

    // TODO: validate the entire message
    //requestError = validate(pubMeth);

    for (QtSoapStructIterator it(pubMeth); it.current() && !requestError; ++it) {
        QtSoapStruct *pubItem = (QtSoapStruct *)it.data();
        QString pubOperation = pubItem->name().name();
        if (_debug.testFlag(Server::ShowClientOps)) {
            qDebug() << fnName << "Publish operation:" << pubOperation;
        }
        if (pubOperation.compare("update", Qt::CaseInsensitive) == 0) {

            QDomDocument doc("placeholder");
            QDomElement el = pubItem->toDomElement(doc);
            doc.appendChild(el);

            Meta::Lifetime lifetime;
            if (_mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
                // Default behavior is metadata lasts until deleted
                lifetime = Meta::LifetimeForever;
            }

            QDomNodeList meta = doc.elementsByTagName("metadata").at(0).childNodes();
            if (meta.isEmpty()) {
                // Error
                requestError = ::IfmapInvalidMetadata;
                continue;
            }

            QList<Meta> publisherMetaList = metaFromNodeList(meta, lifetime, publisherId, &requestError);

            QDomNodeList ids;
            if (_mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
                ids = doc.elementsByTagName("identifier");
            }
            int idCount = 0;
            Link key = keyFromNodeList(ids, &idCount, &requestError);
            if (requestError != ::ErrorNone) {
                // Error with identifier(s) is set in keyFromNodeList
                continue;
            }
            if (_debug.testFlag(Server::ShowClientOps)) {
                qDebug() << fnName << "number of identifiers:" << idCount;
            }
            bool isLink = (idCount == 2) ? true : false;

            if (pubOperation.compare("update", Qt::CaseInsensitive) == 0) {
                _mapGraph->addMeta(key, isLink, publisherMetaList, publisherId);

                // update subscriptions
                updateSubscriptions(key, isLink, publisherMetaList, Meta::PublishUpdate);
            }

        } else if (pubOperation.compare("delete", Qt::CaseInsensitive) == 0) {
            QDomDocument doc("placeholder");
            QDomElement el = pubItem->toDomElement(doc);
            doc.appendChild(el);

            QString filter = QString();
            bool haveFilter = el.attributes().contains("filter");
            if (haveFilter) {
                filter = el.attributes().namedItem("filter").toAttr().value();
                filter = SearchGraph::translateFilter(filter);
                if (_debug.testFlag(Server::ShowClientOps)) {
                    qDebug() << fnName << "delete filter:" << filter;
                }
            } else {
                qDebug() << fnName << "no delete filter provided, deleting ALL metadata";
            }

            QDomNodeList ids;
            if (_mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
                ids = doc.elementsByTagName("identifier");
            }
            int idCount = 0;
            Link key = keyFromNodeList(ids, &idCount, &requestError);
            if (requestError != ::ErrorNone) {
                // Error with identifier(s) is set in keyFromNodeList
                continue;
            }
            if (_debug.testFlag(Server::ShowClientOps)) {
                qDebug() << fnName << "number of identifiers:" << idCount;
            }
            bool isLink = (idCount == 2) ? true : false;

            QList<Meta> existingMetaList;
            if (isLink) existingMetaList = _mapGraph->metaForLink(key);
            else existingMetaList = _mapGraph->metaForId(key.first);

            bool metadataDeleted = false;

            QList<Meta> keepMetaList;
            QList<Meta> deleteMetaList;

            if (! existingMetaList.isEmpty() && haveFilter) {
                QListIterator<Meta> metaListIt(existingMetaList);
                while (metaListIt.hasNext()) {
                    Meta aMeta = metaListIt.next();
                    /* First need to know if the delete filter will match anything,
                       because if it does match, then we'll need to notify any
                       active subscribers.
                    */
                    int dSize = filteredMetadata(aMeta, filter);
                    if (dSize == 0) {
                        // Keep this metadata (delete filter did not match)
                        keepMetaList.append(aMeta);
                        if (_debug.testFlag(Server::ShowClientOps)) {
                            qDebug() << fnName << "Found Meta to keep:" << aMeta.elementName();
                        }
                    } else if (dSize > 0) {
                        deleteMetaList.append(aMeta);
                        if (_debug.testFlag(Server::ShowClientOps)) {
                            qDebug() << fnName << "Meta will be deleted:" << aMeta.elementName();
                        }
                        // Delete matched something, so this may affect subscriptions
                        metadataDeleted = true;
                    } else {
                        // There was an error running the query
                        // Error - ServerError
                        requestError = ::IfmapSystemError;
                    }
                }

                if (metadataDeleted) {
                    if (_debug.testFlag(Server::ShowClientOps)) {
                        qDebug() << fnName << "Updating map graph because metadata was deleted";
                    }
                    _mapGraph->replaceMeta(key, isLink, keepMetaList);
                }

            } else if (! existingMetaList.isEmpty()) {
                // Default 3rd parameter on replaceMeta (empty QList) implies no meta to replace
                // No filter provided so we just delete all metadata
                _mapGraph->replaceMeta(key, isLink);
                metadataDeleted = true;
                deleteMetaList = existingMetaList;
            } else {
                if (_debug.testFlag(Server::ShowClientOps)) {
                    qDebug() << fnName << "No metadata to delete!";
                }
            }

            if (metadataDeleted && !requestError) {
                updateSubscriptions(key, isLink, deleteMetaList, Meta::PublishDelete);
            }
        } else {
            // Error!
            requestError = ::IfmapClientSoapFault;
            qDebug() << fnName << "Client Error: Invalid publish sub-operation:" << pubOperation;
        }
    }

    // The entire publish operation
    // MUST appear atomic to other clients.  So if multiple sub-operations, they need
    // to ALL be applied before any other search is allowed, or subscriptions matched.

    // At this point all the publishes have occurred, we can check subscriptions
    if (!requestError) {
        emit checkActivePolls();
        if (_debug.testFlag(Server::ShowMAPGraphAfterChange)) {
            _mapGraph->dumpMap();
        }
    }

    QtSoapMessage respMsg = soapResponseMsg(soapResponseForOperation("publish", requestError), requestError);
    if (!respMsg.isFault() && _mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
        QtSoapType *sessIdItem = new QtSoapSimpleType(QtSoapQName("session-id", IFMAP_NS_1),sessId);
        respMsg.addHeaderItem(sessIdItem);
    }
    sendResponse(socket, respMsg);
}

void Server::processSubscribe(QTcpSocket *socket, QtSoapMessage reqMsg)
{
    const char *fnName = "Server::processSubscribe:";

    QString sessId;
    IFMAP_ERRORCODES_1 requestError = validateSessionId(reqMsg, socket, &sessId);
    QString publisherId = _activeSSRCSessions.key(sessId);

    if (_debug.testFlag(Server::ShowClientOps)) {
        qDebug() << fnName << "Will manage subscriptions for publisher:" << publisherId;
    }
    QtSoapStruct &subMeth = (QtSoapStruct &)reqMsg.method();

    for (QtSoapStructIterator it(subMeth); it.current() && !requestError; ++it) {
        QtSoapStruct *subItem = (QtSoapStruct *)it.data();
        QString subOperation = subItem->name().name();
        if (_debug.testFlag(Server::ShowClientOps)) {
            qDebug() << fnName << "Subscribe operation:" << subOperation;
        }
        if (subOperation.compare("update", Qt::CaseInsensitive) == 0) {

            QDomDocument doc("placeholder");
            QDomElement el = subItem->toDomElement(doc);
            doc.appendChild(el);

            QString subName;
            if (subItem->attributes().contains("name")) {
                subName = subItem->attributes().namedItem("name").toAttr().value();
                if (_debug.testFlag(Server::ShowClientOps)) {
                    qDebug() << fnName << "Subscription name:" << subName;
                }
            } else {
                // Error
                requestError = ::IfmapClientSoapFault;
                qDebug() << fnName << "Client Error: Missing update subscription name";
                continue;
            }

            QDomNodeList ids;
            if (_mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
                ids = doc.elementsByTagName("identifier");
            }
            int idCount = 0;
            Link key = keyFromNodeList(ids, &idCount, &requestError);
            if (requestError != ::ErrorNone) {
                // Error with identifier(s) is set in keyFromNodeList
                continue;
            } else if (idCount != 1) {
                qDebug() << fnName << "Client Error: Invalid number of identifiers in subscription:" << idCount;
                requestError = ::IfmapClientSoapFault;
                continue;
            }

            Id startingId = key.first;
            QString matchLinks, resultFilter;
            int maxDepth, maxSize;
            requestError = searchParameters(subItem->attributes(), &maxDepth, &matchLinks, &maxSize, &resultFilter);

            if (!requestError) {
                // Only store one subscription list per client
                QSet<Id> idList;
                QSet<Link > linkList;
                int currentDepth = -1;
                buildSearchGraph(startingId, matchLinks, maxDepth, currentDepth, &idList, &linkList);

                if (_debug.testFlag(Server::ShowClientOps)) {
                    qDebug() << fnName << "Subscription:" << subName;
                    qDebug() << fnName << "    idList size:" << idList.size();
                    qDebug() << fnName << "    linkList size:" << linkList.size();
                }

                SearchGraph sub;
                sub.name = subName;
                sub.startId = startingId;
                sub.maxDepth = maxDepth;
                sub.matchLinks = matchLinks;
                sub.maxSize = maxSize;
                sub.resultFilter = resultFilter;
                sub.idList = idList;
                sub.linkList = linkList;

                QtSoapStruct *searchResult = new QtSoapStruct(QtSoapQName("searchResult"));
                searchResult->setAttribute("name", sub.name);

                IFMAP_ERRORCODES_1 addError = ::ErrorNone;
                int sSize = addSearchResultsWithResultFilter(searchResult, sub.maxSize, sub.matchLinks, sub.resultFilter, sub.idList, sub.linkList, &addError);
                sub.curSize += sSize;

                sub.response.insert(searchResult);

                // Check if we have exceeded our max size for the subscription
                if (sub.curSize > sub.maxSize) {
                    qDebug() << fnName << "search results exceeded max-size with curSize:" << sub.curSize;
                    sub.hasErrorResult = true;

                    // TODO: Do I need to delete searchResult?
                    sub.response.clear();

                    QString errString = Server::errorString(::IfmapPollResultsTooBig);
                    QtSoapStruct *errorResult = new QtSoapStruct(QtSoapQName("errorResult"));
                    errorResult->setAttribute("errorCode",errString);
                    errorResult->setAttribute("name", sub.name);

                    sub.response.insert(errorResult);
                }

                QList<SearchGraph> subList = _subscriptionLists.value(publisherId);
                if (subList.isEmpty()) {
                    subList << sub;
                } else {
                    // Replace any existing subscriptions with the same name
                    subList.removeOne(sub);
                    subList << sub;
                }
                if (_debug.testFlag(Server::ShowClientOps)) {
                    qDebug() << fnName << "subList size:" << subList.size();
                }

                _subscriptionLists.insert(publisherId, subList);
                if (_debug.testFlag(Server::ShowClientOps)) {
                    qDebug() << fnName << "Adding SearchGraph to _subscriptionLists with name:" << subName;
                }

                if (_activePolls.contains(publisherId)) {
                    // signal to check subscriptions for polls
                    emit checkActivePolls();
                }
            }
        } else if (subOperation.compare("delete", Qt::CaseInsensitive) == 0) {
            QString subName;
            if (subItem->attributes().contains("name")) {
                subName = subItem->attributes().namedItem("name").toAttr().value();

                SearchGraph delSub;
                delSub.name = subName;

                QList<SearchGraph> subList = _subscriptionLists.take(publisherId);
                if (! subList.isEmpty()) {
                    subList.removeOne(delSub);
                    if (_debug.testFlag(Server::ShowClientOps)) {
                        qDebug() << fnName << "Removing subscription from subList with name:" << subName;
                    }
                } else {
                    qDebug() << fnName << "No subscriptions to delete for publisher:" << publisherId;
                }

                if (! subList.isEmpty()) {
                    _subscriptionLists.insert(publisherId, subList);
                }

                if (_debug.testFlag(Server::ShowClientOps)) {
                    qDebug() << fnName << "subList size:" << subList.size();
                }
            } else {
                // Error - no name in delete
                requestError = ::IfmapClientSoapFault;
                qDebug() << fnName << "Client Error: Missing delete subscription name";
                continue;
            }
        } else {
            // Error!
            requestError = ::IfmapClientSoapFault;
            qDebug() << fnName << "Client Error: Invalid subscription sub-operation:" << subOperation;
        }
    }

    QtSoapMessage respMsg = soapResponseMsg(soapResponseForOperation("subscribe", requestError), requestError);
    if (!respMsg.isFault() && _mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
        QtSoapType *sessIdItem = new QtSoapSimpleType(QtSoapQName("session-id", IFMAP_NS_1),sessId);
        respMsg.addHeaderItem(sessIdItem);
    }
    sendResponse(socket, respMsg);
}

void Server::processSearch(QTcpSocket *socket, QtSoapMessage reqMsg)
{
    const char *fnName = "Server::processSearch:";
    QtSoapStruct *searchResponse;

    QString sessId;
    IFMAP_ERRORCODES_1 requestError = validateSessionId(reqMsg, socket, &sessId);

    QtSoapStruct &searchMeth = (QtSoapStruct&)reqMsg.method();
    QDomDocument doc("placeholder");
    QDomElement el = searchMeth.toDomElement(doc);
    doc.appendChild(el);

    QDomNodeList ids;
    if (_mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
        ids = doc.elementsByTagName("identifier");
    }
    int idCount = 0;
    Link key = keyFromNodeList(ids, &idCount, &requestError);
    if (requestError != ::ErrorNone) {
        qDebug() << fnName << "Client Error: Error parsing identifiers:" << requestError;
        searchResponse = (QtSoapStruct *)soapResponseForOperation("search", requestError);
    } else if (idCount != 1) {
        // Don't need to allocate searchResponse for ::IfmapClientSoapFault
        requestError = ::IfmapClientSoapFault;
        qDebug() << fnName << "Client Error: Incorrect number of identifiers in search:" << idCount;
    } else {
        Id startingId = key.first;

        QString matchLinks, resultFilter;
        int maxDepth, maxSize;
        requestError = searchParameters(searchMeth.attributes(), &maxDepth, &matchLinks, &maxSize, &resultFilter);

        if (!requestError) {
            QSet<Id> idList;
            QSet<Link > linkList;
            int currentDepth = -1;
            buildSearchGraph(startingId, matchLinks, maxDepth, currentDepth, &idList, &linkList);

            if (_debug.testFlag(Server::ShowClientOps)) {
                qDebug() << fnName << "Search Lists";
                qDebug() << fnName << "    idList size:" << idList.size();
                qDebug() << fnName << "    linkList size:" << linkList.size();
            }

            searchResponse = (QtSoapStruct *)soapResponseForOperation("search", requestError);
            addSearchResultsWithResultFilter(searchResponse, maxSize, matchLinks, resultFilter, idList, linkList, &requestError);
            if (requestError == ::IfmapClientSoapFault) {
                delete searchResponse;
            } else if (requestError != ::ErrorNone) {
                delete searchResponse;
                searchResponse = (QtSoapStruct *)soapResponseForOperation("search", requestError);
            }
        }
    }

    QtSoapMessage respMsg = soapResponseMsg(searchResponse, requestError);
    if (!respMsg.isFault() && _mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
        QtSoapType *sessIdItem = new QtSoapSimpleType(QtSoapQName("session-id", IFMAP_NS_1),sessId);
        respMsg.addHeaderItem(sessIdItem);
    }
    sendResponse(socket, respMsg);

}

void Server::processPurgePublisher(QTcpSocket *socket, QtSoapMessage reqMsg)
{
    const char *fnName = "Server::processPurgePublisher:";

    QString sessId;
    IFMAP_ERRORCODES_1 requestError = validateSessionId(reqMsg, socket, &sessId);
    QString publisherId = _activeSSRCSessions.key(sessId);

    QString purgePubId, purgePubIdAttrName;
    if (_mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
        purgePubIdAttrName = "publisher-id";
    }

    if (reqMsg.method().attributes().contains(purgePubIdAttrName)) {
        purgePubId = reqMsg.method().attributes().namedItem(purgePubIdAttrName).toAttr().value();
        if (_debug.testFlag(Server::ShowClientOps)) {
            qDebug() << fnName << "Got purgePublisher publisher-id:" << purgePubId;
        }

        if (purgePubId.compare(publisherId) != 0) {
            //requestError = ::IfmapAccessDenied;
            qDebug() << fnName << "Computed publisher-id and purgePublisher attribute do NOT match";
        }

        if (!requestError) {
            QHash<Id, QList<Meta> > idMetaDeleted;
            QHash<Link, QList<Meta> > linkMetaDeleted;
            bool haveChange = _mapGraph->deleteMetaWithPublisherId(purgePubId, &idMetaDeleted, &linkMetaDeleted);

            // Check subscriptions for changes to Map Graph
            if (haveChange) {
                updateSubscriptions(idMetaDeleted, linkMetaDeleted);
                emit checkActivePolls();
                if (_debug.testFlag(Server::ShowMAPGraphAfterChange)) {
                    _mapGraph->dumpMap();
                }
            }
        }
    } else {
        // Error!
        requestError = ::IfmapClientSoapFault;
        qDebug() << fnName << "Client Error:" << purgePubIdAttrName << "attribute missing in purgePublisher method";
    }

    QtSoapMessage respMsg = soapResponseMsg(soapResponseForOperation("purgePublisher", requestError), requestError);
    if (!respMsg.isFault() && _mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
        QtSoapType *sessIdItem = new QtSoapSimpleType(QtSoapQName("session-id", IFMAP_NS_1),sessId);
        respMsg.addHeaderItem(sessIdItem);
    }
    sendResponse(socket, respMsg);
}

void Server::processPoll(QTcpSocket *socket, QtSoapMessage reqMsg)
{
    const char *fnName = "Server::processPoll:";

    QString sessId;
    IFMAP_ERRORCODES_1 requestError = validateSessionId(reqMsg, socket, &sessId);
    QString publisherId = _activeSSRCSessions.key(sessId);

    if (!requestError) {
        if (_activeARCSessions.contains(publisherId)) {
            // Track the TCP socket this publisher's poll is on
            _activePolls.insert(publisherId, socket);

            if (_subscriptionLists.value(publisherId).isEmpty()) {
                // No immediate client response
                if (_debug.testFlag(Server::ShowClientOps)) {
                    qDebug() << fnName << "No subscriptions for publisherId:" << publisherId;
                }
            } else {
                emit checkActivePolls();
            }
        } else {
            // Error
            requestError = ::IfmapInvalidSessionID;
            qDebug() << fnName << "No active ARC session for poll from publisherId:" << publisherId;
        }
    }

    if (requestError) {
        if (_subscriptionLists.contains(publisherId)) {
            _subscriptionLists.remove(publisherId);
            qDebug() << fnName << "Removing subscriptions for publisherId:" << publisherId;
        }
        QtSoapMessage respMsg = soapResponseMsg(soapResponseForOperation("poll", requestError), requestError);
        if (!respMsg.isFault() && _mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
            QtSoapType *sessIdItem = new QtSoapSimpleType(QtSoapQName("session-id", IFMAP_NS_1),sessId);
            respMsg.addHeaderItem(sessIdItem);
        }
        sendResponse(socket, respMsg);
    }
}

bool Server::terminateSession(QString sessionId)
{
    const char *fnName = "Server::terminateSession";
    bool hadExistingSession = false;

    // Remove sessionId from list of active SSRC Sessions
    QString publisherId = _activeSSRCSessions.key(sessionId);

    if (! publisherId.isEmpty()) {
        hadExistingSession = true;

        _activeSSRCSessions.remove(sessionId);

        if (_subscriptionLists.contains(publisherId)) {
            _subscriptionLists.remove(publisherId);
            if (_debug.testFlag(Server::ShowClientOps)) {
                qDebug() << fnName << "Removing subscriptions for publisherId:" << publisherId;
            }
        }

        terminateARCSession(sessionId);

        // Delete all session-level metadata for this publisher
        QHash<Id, QList<Meta> > idMetaDeleted;
        QHash<Link, QList<Meta> > linkMetaDeleted;
        bool haveChange = _mapGraph->deleteMetaWithPublisherId(publisherId, &idMetaDeleted, &linkMetaDeleted, true);
        // Check subscriptions for changes to Map Graph
        if (haveChange) {
            updateSubscriptions(idMetaDeleted, linkMetaDeleted);
            emit checkActivePolls();
            if (_debug.testFlag(Server::ShowMAPGraphAfterChange)) {
                _mapGraph->dumpMap();
            }
        }
    }

    return hadExistingSession;
}

bool Server::terminateARCSession(QString sessionId)
{
    const char *fnName = "Server::terminateARCSession:";
    bool hadExistingARCSession = false;

    QString publisherId = _activeARCSessions.key(sessionId);

    if (! publisherId.isEmpty()) {
        hadExistingARCSession = true;

        // End active ARC Session
        _activeARCSessions.remove(publisherId);
        qDebug() << fnName << "Ending active ARC Session for publisherId:" << publisherId;

        // Terminate polls
        if (_activePolls.contains(publisherId)) {
            _activePolls.remove(publisherId);
            qDebug() << fnName << "Terminated active poll for publisherId:" << publisherId;
        }
    }

    return hadExistingARCSession;
}

IFMAP_ERRORCODES_1 Server::searchParameters(QDomNamedNodeMap searchAttrs, int *maxDepth, QString *matchLinks, int *maxSize, QString *resultFilter)
{
    const char *fnName = "Server::searchParameters:";

    if (searchAttrs.contains("max-depth")) {
        QString md = searchAttrs.namedItem("max-depth").toAttr().value();
        bool ok;
        *maxDepth = md.toInt(&ok);
        if (ok) {
            if (_debug.testFlag(Server::ShowClientOps)) {
                qDebug() << fnName << "Got search parameter max-depth:" << *maxDepth;
            }
            if (*maxDepth < 0) *maxDepth = IFMAP_MAX_DEPTH_MAX;
        } else {
            return ::IfmapClientSoapFault;
        }
    } else {
        *maxDepth = 0;
        qDebug() << fnName << "Using default search parameter max-depth:" << *maxDepth;
    }

    if (searchAttrs.contains("match-links")) {
        QString ifmapMatchLinks = searchAttrs.namedItem("match-links").toAttr().value();
        *matchLinks = SearchGraph::translateFilter(ifmapMatchLinks);
        if (_debug.testFlag(Server::ShowClientOps)) {
            qDebug() << fnName << "Got search parameter match-links:" << *matchLinks;
        }
    } else {
        *matchLinks = QString("");
        qDebug() << fnName << "Using default search parameter match-links:" << *matchLinks;
    }

    if (searchAttrs.contains("max-size")) {
        QString ms = searchAttrs.namedItem("max-size").toAttr().value();
        bool ok;
        *maxSize = ms.toInt(&ok);
        if (ok) {
            if (_debug.testFlag(Server::ShowClientOps)) {
                qDebug() << fnName << "Got search parameter max-size:" << *maxSize;
            }
        } else
            return ::IfmapClientSoapFault;
    } else {
        *maxSize = IFMAP_MAX_SIZE;
        qDebug() << fnName << "Using default search parameter max-size:" << *maxSize;
    }

    if (searchAttrs.contains("result-filter")) {
        QString ifmapResultFilter = searchAttrs.namedItem("result-filter").toAttr().value();
        *resultFilter = SearchGraph::translateFilter(ifmapResultFilter);
        if (_debug.testFlag(Server::ShowClientOps)) {
            qDebug() << fnName << "Got search parameter result-filter:" << *resultFilter;
        }
    } else {
        *resultFilter = QString("*");
        qDebug() << fnName << "Using default search parameter result-filter:" << *resultFilter;
    }

    return ::ErrorNone;
}

QString Server::errorString(IFMAP_ERRORCODES_1 error)
{
    QString str("");

    switch (error) {
        case ::ErrorNone:
            break;
        case ::IfmapClientSoapFault:
            break;
        case ::IfmapAccessDenied:
            str = "AccessDenied";
            break;
        case ::IfmapFailure:
            str = "Failure";
            break;
        case ::IfmapInvalidIdentifier:
            str = "InvalidIdentifier";
            break;
        case ::IfmapInvalidIdentifierType:
            str = "InvalidIdentifierType";
            break;
        case ::IfmapIdentifierTooLong:
            str = "IdentifierTooLong";
            break;
        case ::IfmapInvalidMetadata:
            str = "InvalidMetadata";
            break;
        case ::IfmapInvalidMetadataListType:
            str = "InvalidMetadataListType";
            break;
        case ::IfmapInvalidSchemaVersion:
            str = "InvalidSchemaVersion";
            break;
        case ::IfmapInvalidSessionID:
            str = "InvalidSessionID";
            break;
        case ::IfmapMetadataTooLong:
            str = "MetadataTooLong";
            break;
        case ::IfmapSearchResultsTooBig:
            str = "SearchResultsTooBig";
            break;
        case ::IfmapPollResultsTooBig:
            str = "PollResultsTooBig";
            break;
        case ::IfmapSystemError:
            str = "SystemError";
            break;
    }

    return str;
}

QtSoapMessage Server::soapResponseMsg(QtSoapType *content, IFMAP_ERRORCODES_1 errorCode)
{
    QtSoapMessage msg;

    if (errorCode == ::IfmapClientSoapFault) {
        msg.setFaultCode(QtSoapMessage::Client);
        msg.setFaultString("Client Error");
    } else {
        QtSoapStruct *respStruct;
        if (_mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
            respStruct = new QtSoapStruct(QtSoapQName("response", IFMAP_NS_1));
        }
        respStruct->insert(content);
        msg.addBodyItem(respStruct);
    }

    return msg;
}

QtSoapType* Server::soapResponseForOperation(QString operation, IFMAP_ERRORCODES_1 operationError)
{
    const char *fnName = "Server::soapResponseForOperation:";
    QtSoapType *respMsg = 0;

    if (operationError == ::IfmapClientSoapFault) {
        // No point building a response for SOAP Fault, it won't get used
        return respMsg;
    } else if (operationError) {
        qDebug() << fnName << "Generating errorResult from error in Client request:" << operation;
        QString errString = Server::errorString(operationError);
        respMsg = new QtSoapStruct(QtSoapQName("errorResult"));
        respMsg->setAttribute("errorCode",errString);
    } else if (operation.compare("newSession", Qt::CaseInsensitive) == 0) {
        respMsg = new QtSoapSimpleType(QtSoapQName("newSessionResult"));
    } else if (operation.compare("renewSession", Qt::CaseInsensitive) == 0) {
        respMsg = new QtSoapSimpleType(QtSoapQName("renewSessionResult"));
    } else if (operation.compare("endSession", Qt::CaseInsensitive) == 0) {
        respMsg = new QtSoapSimpleType(QtSoapQName("endSessionResult"));
    } else if (operation.compare("attachSession", Qt::CaseInsensitive) == 0) {
        respMsg = new QtSoapSimpleType(QtSoapQName("attachSessionResult"));
    } else if (operation.compare("publish", Qt::CaseInsensitive) == 0) {
        respMsg = new QtSoapSimpleType(QtSoapQName("publishReceived"));
    } else if (operation.compare("search", Qt::CaseInsensitive) == 0) {
        respMsg = new QtSoapStruct(QtSoapQName("searchResult"));
    } else if (operation.compare("subscribe", Qt::CaseInsensitive) == 0) {
        respMsg = new QtSoapSimpleType(QtSoapQName("subscribeReceived"));
    } else if (operation.compare("poll", Qt::CaseInsensitive) == 0) {
        respMsg = new QtSoapStruct(QtSoapQName("pollResult"));
    } else if (operation.compare("purgePublisher", Qt::CaseInsensitive) == 0) {
        respMsg = new QtSoapSimpleType(QtSoapQName("purgePublishReceived"));
    }

    return respMsg;
}

QtSoapType* Server::soapStructForId(Id id)
{
    QtSoapType *soapId = 0;
    QtSoapSimpleType *device;
    switch(id.type()) {
        case Identifier::IdNone:
            break;
        case Identifier::AccessRequest:
            soapId = new QtSoapSimpleType(QtSoapQName("access-request"));
            soapId->setAttribute("name",id.value());
            break;
        case Identifier::DeviceAikName:
            soapId = new QtSoapStruct(QtSoapQName("device"));
            device = new QtSoapSimpleType(QtSoapQName("aik-name"),id.value());
            ((QtSoapStruct *)soapId)->insert(device);
            break;
        case Identifier::DeviceName:
            soapId = new QtSoapStruct(QtSoapQName("device"));
            device = new QtSoapSimpleType(QtSoapQName("name"),id.value());
            ((QtSoapStruct *)soapId)->insert(device);
            break;
        case Identifier::IpAddressIPv4:
            soapId = new QtSoapSimpleType(QtSoapQName("ip-address"));
            soapId->setAttribute("type","IPv4");
            soapId->setAttribute("value", id.value());
            break;
        case Identifier::IpAddressIPv6:
            soapId = new QtSoapSimpleType(QtSoapQName("ip-address"));
            soapId->setAttribute("type","IPv6");
            soapId->setAttribute("value", id.value());
            break;
        case Identifier::MacAddress:
            soapId = new QtSoapSimpleType(QtSoapQName("mac-address"));
            soapId->setAttribute("value", id.value());
            break;
        case Identifier::IdentityAikName:
            soapId = new QtSoapSimpleType(QtSoapQName("identity"));
            soapId->setAttribute("name", id.value());
            soapId->setAttribute("type", "aik-name");
            break;
        case Identifier::IdentityDistinguishedName:
            soapId = new QtSoapSimpleType(QtSoapQName("identity"));
            soapId->setAttribute("name", id.value());
            soapId->setAttribute("type", "distinguished-name");
            break;
        case Identifier::IdentityDnsName:
            soapId = new QtSoapSimpleType(QtSoapQName("identity"));
            soapId->setAttribute("name", id.value());
            soapId->setAttribute("type", "dns-name");
            break;
        case Identifier::IdentityEmailAddress:
            soapId = new QtSoapSimpleType(QtSoapQName("identity"));
            soapId->setAttribute("name", id.value());
            soapId->setAttribute("type", "email-address");
            break;
        case Identifier::IdentityKerberosPrincipal:
            soapId = new QtSoapSimpleType(QtSoapQName("identity"));
            soapId->setAttribute("name", id.value());
            soapId->setAttribute("type", "kerberos-principal");
            break;
        case Identifier::IdentityTrustedPlatformModule:
            soapId = new QtSoapSimpleType(QtSoapQName("identity"));
            soapId->setAttribute("name", id.value());
            soapId->setAttribute("type", "trusted-platform-module");
            break;
        case Identifier::IdentityUsername:
            soapId = new QtSoapSimpleType(QtSoapQName("identity"));
            soapId->setAttribute("name", id.value());
            soapId->setAttribute("type", "username");
            break;
        case Identifier::IdentitySipUri:
            soapId = new QtSoapSimpleType(QtSoapQName("identity"));
            soapId->setAttribute("name", id.value());
            soapId->setAttribute("type", "sip-uri");
            break;
        case Identifier::IdentityHipHit:
            soapId = new QtSoapSimpleType(QtSoapQName("identity"));
            soapId->setAttribute("name", id.value());
            soapId->setAttribute("type", "hip-hit");
            break;
        case Identifier::IdentityTelUri:
            soapId = new QtSoapSimpleType(QtSoapQName("identity"));
            soapId->setAttribute("name", id.value());
            soapId->setAttribute("type", "tel-uri");
            break;
        case Identifier::IdentityOther:
            soapId = new QtSoapSimpleType(QtSoapQName("identity"));
            soapId->setAttribute("name", id.value());
            soapId->setAttribute("type", "other");
            soapId->setAttribute("other-type-definition", id.other());
            break;
    }

    if ( id.type() != Identifier::DeviceAikName && id.type() != Identifier::DeviceName
         && !(id.ad().isEmpty()) ) {
        soapId->setAttribute("administrative-domain", id.ad());
    }

    if (_mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
        QtSoapStruct *idOuterStruct = new QtSoapStruct(QtSoapQName("identifier"));
        idOuterStruct->insert(soapId);
        return idOuterStruct;
    }

    return 0;
}

QList<Meta> Server::metaFromNodeList(QDomNodeList metaNodes, Meta::Lifetime lifetime, QString publisherId, IFMAP_ERRORCODES_1 *errorCode)
{
    const char *fnName = "Server::metaFromNodeList:";
    QList<Meta> metaList;

    QString pubIdAttrName, timestampAttrName, cardinalityAttrName;
    if (_mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
        pubIdAttrName = "publisher-id";
        timestampAttrName = "timestamp";
        cardinalityAttrName = "cardinality";
    }

    if (_debug.testFlag(Server::ShowClientOps)) {
        qDebug() << fnName << "number of metadata nodes:" << metaNodes.count();
    }

    for (int i=0; i<metaNodes.count(); i++) {
        QString metaName = metaNodes.at(i).localName();
        QString metaNS = metaNodes.at(i).namespaceURI();
        QString metaPrefix = metaNodes.at(i).prefix();
        QString cardinality = metaNodes.at(i).attributes().namedItem(cardinalityAttrName).toAttr().value();
        Meta::Cardinality cardinalityValue = (cardinality == "multiValue") ? Meta::MultiValue : Meta::SingleValue;

        // TODO: Perform comprehensive metadata validation if desired

        // Check metadata has a qualified namespace and register it in global namespace registry
        if (metaNS.isEmpty() || metaPrefix.isEmpty()) {
            *errorCode = ::IfmapInvalidMetadata;
            qDebug() << fnName << "Client Error: metadata does not have associated namespace:" << metaName;
            continue;
        } else {
            QtSoapNamespaces ns = QtSoapNamespaces::instance();
            if (!ns.namespaceRegistered(metaNS)) {
                qDebug() << fnName << "Registering prefix:" << metaPrefix << "for namespace:" << metaNS;
                ns.registerNamespace(metaPrefix, metaNS);
            } else {
                QString aPrefix = ns.prefixFor(metaNS);
                qDebug() << fnName << "Have already registered namespace:" << metaNS
                        << "with prefix:" << aPrefix;
            }
        }

        // Add publisherId to meta node
        metaNodes.at(i).toElement().setAttribute(pubIdAttrName,publisherId);
        // Add timestamp to meta node
        /* The dateTime is specified in the following form "YYYY-MM-DDThh:mm:ss" where:
            * YYYY indicates the year
            * MM indicates the month
            * DD indicates the day
            * T indicates the start of the required time section
            * hh indicates the hour
            * mm indicates the minute
            * ss indicates the second
            Note: All components are required!
        */
        metaNodes.at(i).toElement().setAttribute(timestampAttrName,QDateTime::currentDateTime().toUTC().toString("yyyy-MM-ddThh:mm:ss"));

        QDomNode metaDomNode = metaNodes.at(i);

        Meta aMeta(cardinalityValue, lifetime);
        aMeta.setElementName(metaName);
        aMeta.setNamespace(metaNS);
        aMeta.setMetaNode(metaDomNode.cloneNode());
        aMeta.setPublisherId(publisherId);

        metaList << aMeta;
    }

    return metaList;
}

Link Server::keyFromNodeList(QDomNodeList ids, int *idCount, IFMAP_ERRORCODES_1 *errorCode)
{
    Link key;
    Id id1;
    Id id2;

    if (_mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
        if (ids.isEmpty() || ids.length() > 2) {
            *errorCode = ::IfmapClientSoapFault;
        } else {
            bool isLink = (ids.length() == 2) ? true : false;
            if (! isLink) {
                id1 = idFromNode(ids.at(0).firstChild(), errorCode);
                *idCount = 1;
            } else {
                id1 = idFromNode(ids.at(0).firstChild(), errorCode);
                id2 = idFromNode(ids.at(1).firstChild(), errorCode);
                *idCount = 2;
            }
        }
    }

    if (*errorCode == ::ErrorNone && *idCount == 1) {
        key.first = id1;
    } else if (*errorCode == ::ErrorNone && *idCount == 2) {
        key = Identifier::makeLinkFromIds(id1, id2);
    } else {
        *errorCode = ::IfmapClientSoapFault;
    }

    return key;
}

Id Server::idFromNode(QDomNode idNode, IFMAP_ERRORCODES_1 *errorCode)
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
            if (_debug.testFlag(Server::ShowClientOps)) {
                qDebug() << fnName << "Got access-request name:" << value;
            }
        } else {
            // Error - did not specify access-request name
            parseError = true;
            *errorCode = ::IfmapInvalidIdentifier;
        }
    } else if (idName.compare("device", Qt::CaseInsensitive) == 0) {
        QString deviceType = idNode.firstChildElement().tagName();
        if (deviceType.compare("aik-name", Qt::CaseInsensitive) == 0) {
            idType = Identifier::DeviceAikName;
            value = idNode.firstChildElement().text();
            if (_debug.testFlag(Server::ShowClientOps)) {
                qDebug() << fnName << "Got device aik-name:" << value;
            }
        } else if (deviceType.compare("name", Qt::CaseInsensitive) == 0) {
            idType = Identifier::DeviceName;
            value = idNode.firstChildElement().text();
            if (_debug.testFlag(Server::ShowClientOps)) {
                qDebug() << fnName << "Got device name:" << value;
            }
        } else {
            // Error - unknown device type
            parseError = true;
            *errorCode = ::IfmapInvalidIdentifier;
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
            } else if (type.compare("email-address", Qt::CaseInsensitive) == 0) {
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
                *errorCode = ::IfmapInvalidIdentifierType;
            }
        } else {
            // Error - did not specify identity type
            parseError = true;
            *errorCode = ::IfmapInvalidIdentifier;
        }

        if (attrs.contains("name")) {
            value = attrs.namedItem("name").toAttr().value();
            if (_debug.testFlag(Server::ShowClientOps)) {
                qDebug() << fnName << "Got identity name:" << value;
            }
        } else {
            // Error - did not specify identity name attribute
            parseError = true;
            *errorCode = ::IfmapInvalidIdentifier;
        }

        if (idType == Identifier::IdentityOther) {
            if (attrs.contains("other-type-definition")) {
                // Append other-type-definition to value
                other = attrs.namedItem("other-type-definition").toAttr().value();
                if (_debug.testFlag(Server::ShowClientOps)) {
                    qDebug() << fnName << "Got identity other-type-def:" << other;
                }
            } else {
                // Error - MUST have other-type-definition if idType is IdentityOther
                parseError = true;
                *errorCode = ::IfmapInvalidIdentifier;
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
                *errorCode = ::IfmapInvalidIdentifier;
            }
        } else {
            idType = Identifier::IpAddressIPv4;
        }

        if (attrs.contains("value")) {
            value = attrs.namedItem("value").toAttr().value();
            if (_debug.testFlag(Server::ShowClientOps)) {
                qDebug() << fnName << "Got ip-address:" << value;
            }
        } else {
            // Error - did not specify ip-address value attribute
            parseError = true;
            *errorCode = ::IfmapInvalidIdentifier;
        }

    } else if (idName.compare("mac-address", Qt::CaseInsensitive) == 0) {
        idType = Identifier::MacAddress;

        if (attrs.contains("value")) {
            value = attrs.namedItem("value").toAttr().value();
            if (_debug.testFlag(Server::ShowClientOps)) {
                qDebug() << fnName << "Got mac-address:" << value;
            }
        } else {
            // Error - did not specify mac-address value attribute
            parseError = true;
            *errorCode = ::IfmapInvalidIdentifier;
        }
    } else {
        // Error - unknown identifier name
        parseError = true;
        *errorCode = ::IfmapInvalidIdentifierType;
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

Id Server::otherIdForLink(Link link, Id targetId)
{
    if (link.first == targetId)
        return link.second;
    else
        return link.first;
}

int Server::filteredMetadata(Meta meta, QString filter, QtSoapStruct *metaResult)
{
    QList<Meta> singleMetaList;
    singleMetaList.append(meta);
    return filteredMetadata(singleMetaList, filter, metaResult);
}

/* Returns -1 on QXmlQuery Error, else string length of metadata results
*/
int Server::filteredMetadata(QList<Meta> metaList, QString filter, QtSoapStruct *metaResult)
{
    const char *fnName = "Server::filteredMetadata:";
    int resultSize = 0;
    bool matchAll = false;

    /* The filter will be either a match-links, result-filter, or delete filter,
       depending on where this method is called.  The "invert" parameter reverses the
       sense of the filter, so if the filter is a delete filter, be sure
       to set invert = true.
    */
    if (filter.isEmpty()) {
        qDebug() << fnName << "Empty filter string matches nothing";
        return 0;
    } else if (filter == "*") {
        matchAll = true;
    }

    QString qString;
    QTextStream queryStream(&qString);

    if (!matchAll) {
        /* TODO: I should be using the namespaces/prefixes sent by the client in their
           <search> element and/or in their match-links and result-filter filter text.
           To get something working, I'm just using the prefix that was used when the
           metadata was published, but this may be a different prefix than what is used
           in filter.  I'm also including the standard IFMAP_META_NS namespace with meta
           prefix that is registered in the Server::Server() method.
        */
        QStringList namespaceList = QtSoapNamespaces::instance().namespaceList();
        QStringListIterator nsit(namespaceList);
        while (nsit.hasNext()) {
            QString nsuri = nsit.next();
            QString prefix = QtSoapNamespaces::instance().prefixFor(nsuri);
            if (!nsuri.isEmpty() && !prefix.isEmpty() &&
                nsuri != SOAPv11_ENVELOPE && nsuri != SOAPv11_ENCODING &&
                nsuri != XML_SCHEMA && nsuri != XML_SCHEMA_INSTANCE &&
                nsuri != IFMAP_NS_1) {
                queryStream << "declare namespace "
                        << prefix
                        << " = \""
                        << nsuri
                        << "\";";
            }
        }

        queryStream << "<metadata>";
    }

    QListIterator<Meta> it2(metaList);
    while (it2.hasNext()) {
        QDomNode metaNode = it2.next().metaNode();
        queryStream << metaNode;
    }

    if (!matchAll) {
        queryStream << "</metadata>";
        queryStream << "//"
                    << filter;
    }

    QString queryStr = queryStream.readAll();

    if (_debug.testFlag(Server::ShowXMLFilterStatements))
        qDebug() << fnName << "Query Statement:" << endl << queryStr;

    QXmlQuery query;
    QString result;
    bool qrc;

    if (!matchAll) {
        query.setQuery(queryStr);
        qrc = query.evaluateTo(&result);
    } else {
        result = queryStr;
        qrc = true;
    }

    if (! qrc) {
        qDebug() << fnName << "Error running query!";
        resultSize = -1;
    } else {
        if (! result.trimmed().isEmpty()) {
            resultSize = result.size();

            if (_debug.testFlag(Server::ShowXMLFilterResults))
                qDebug() << fnName << "Query Result:" << endl << result;

            if (metaResult) {
                result.prepend("<metadata>");
                result.append("</metadata>");

                // Package up result into metaResult
                int errorLine, errorColumn;
                QString errorMsg;
                QDomDocument resultDom;
                if (!resultDom.setContent(result, true, &errorMsg, &errorLine, &errorColumn)) {
                    qDebug() << fnName << "Document parsing errorMsg:" << errorMsg;
                } else {
                    QDomNode node = resultDom.documentElement();
                    bool res = metaResult->parse(node);
                    if (!res) {
                        qDebug() << fnName << "Error parsing QtSoapStruct from DOM node";
                        resultSize = 0;
                    }
                }
            }
        }
    }

    return resultSize;
}

int Server::addSearchResultsWithResultFilter(QtSoapStruct *soapResponse, int maxSize, QString matchLinks, QString resultFilter, QSet<Id> idList, QSet<Link> linkList, IFMAP_ERRORCODES_1 *operationError)
{
    const char *fnName = "Server::addSearchResultsWithResultFilter:";

    QString linkResultName, identifierResultName;
    if (_mapVersionSupport.testFlag(Server::SupportIfmapV11)) {
        linkResultName = "linkResult";
        identifierResultName = "identifierResult";
    }

    int curSize = 0;

    QSetIterator<Link> linkIt(linkList);
    while (linkIt.hasNext() && !(*operationError)) {
        Link link = linkIt.next();
        QList<Meta> linkMetaList = _mapGraph->metaForLink(link);
        if (_debug.testFlag(Server::ShowClientOps)) {
            qDebug() << fnName << "linkMetaList size for link:" << link << "-->" << linkMetaList.size();
        }
        // In this context linkMetaList _may_ be empty if calling this method with delta id list
        if (! linkMetaList.isEmpty()) {
            QtSoapStruct *linkResult = new QtSoapStruct(QtSoapQName(linkResultName));
            QtSoapType *idStruct1 = soapStructForId(link.first);
            QtSoapType *idStruct2 = soapStructForId(link.second);

            QtSoapStruct *metaResult = new QtSoapStruct();
            /* I now interpret the search algorithm to say
               that link metadata returned from a search is first filtered by match-links.
               Then result-filter specifies _further_ rules for deleting data from the
               results.  I initially only applied result-filter to _all_ metadata, and
               used match-links just for building the search graph.  In other words,
               match-links is a whitelist of link metadata and this interpretation of
               match-links keeps clients from discovering link metadata they do
               expect to exist.  The initial behavior may in some cases be desired.
            */
            int mSize;
            if (_nonStdBehavior.testFlag(Server::DoNotUseMatchLinksInSearchResults)) {
                qDebug() << fnName << "NON-STANDARD: Not filtering metadata with match-links";
                mSize = filteredMetadata(linkMetaList, resultFilter, metaResult);
            } else {
                QString combinedFilter = SearchGraph::intersectFilter(matchLinks, resultFilter);
                mSize = filteredMetadata(linkMetaList, combinedFilter, metaResult);
            }

            if (mSize > 0) {
                linkResult->insert(metaResult);
                curSize += mSize;
                if (curSize > maxSize) {
                    qDebug() << fnName << "Search results exceeded max-size with curSize:" << curSize;
                    *operationError = ::IfmapSearchResultsTooBig;
                }
            } else {
                delete metaResult;
            }
            linkResult->insert(idStruct2);
            linkResult->insert(idStruct1);
            soapResponse->insert(linkResult);
        }
    }

    QSetIterator<Id> idIt(idList);
    while (idIt.hasNext() && !(*operationError)) {
        Id id = idIt.next();
        QList<Meta> idMetaList = _mapGraph->metaForId(id);
        // In this context idMetaList _may_ be empty if calling this method with delta id list
        if (! idMetaList.isEmpty()) {
            QtSoapStruct *idResult = new QtSoapStruct(QtSoapQName(identifierResultName));
            QtSoapType *idStruct = soapStructForId(id);

            QtSoapStruct *metaResult = new QtSoapStruct();
            int mSize = filteredMetadata(idMetaList, resultFilter, metaResult);

            if (mSize > 0) {
                idResult->insert(metaResult);
                curSize += mSize;
                if (curSize > maxSize) {
                    qDebug() << fnName << "Search results exceeded max-size with curSize;" << curSize;
                    *operationError = ::IfmapSearchResultsTooBig;
                }
            } else {
                delete metaResult;
            }

            idResult->insert(idStruct);
            soapResponse->insert(idResult);
        }
    }

    return curSize;
}

void Server::buildSearchGraph(Id startId, QString matchLinks, int maxDepth,
                    int currentDepth, // Pass by value!  Must initially be -1.
                    QSet<Id> *idList,
                    QSet<Link > *linkList)
{
    const char *fnName = "Server::buildSearchGraph";

    // 1. Current id, current results, current depth
    currentDepth++;
    if (_debug.testFlag(Server::ShowClientOps)) {
        qDebug() << fnName << "Starting identifier:" << startId;
        qDebug() << fnName << "Current depth:" << currentDepth;
    }

    // 2. Check max depth reached
    if (currentDepth >= maxDepth) {
        if (_debug.testFlag(Server::ShowClientOps)) {
            qDebug() << fnName << "max depth reached:" << maxDepth;
        }
        return;
    }

    // 3. Save current identifier in list of traversed identifiers
    // so we can later gather metadata from these identifiers.
    idList->insert(startId);

    // 5. Get list of links that have startId in link and pass matchLinks filter
    QSet<Link> linksWithCurId;
    QList<Id> startIdLinks = _mapGraph->linksTo(startId);
    QListIterator<Id> idIter(startIdLinks);
    while (idIter.hasNext()) {
        // TODO: Would be nice to exclude the previous startId from this loop

        // matchId is the other end of the link
        Id matchId = idIter.next();
        // Get identifier-order independent link
        Link link = Identifier::makeLinkFromIds(startId, matchId);
        // Get metadata on this link
        QList<Meta> curLinkMeta = _mapGraph->metaForLink(link);
        //If any of this metadata matches matchLinks add link to idMatchList
        if (filteredMetadata(curLinkMeta, matchLinks) > 0) {
            if (_debug.testFlag(Server::ShowClientOps)) {
                qDebug() << fnName << "Adding link:" << link;
            }
            linksWithCurId.insert(link);
        }
    }

    // Remove links we've already seen before
    linksWithCurId.subtract(*linkList);

    if (linksWithCurId.isEmpty()) {
        if (_debug.testFlag(Server::ShowClientOps)) {
            qDebug() << fnName << "linksWithCurId is empty!!!";
        }
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

void Server::updateSubscriptions(QHash<Id, QList<Meta> > idMetaDeleted, QHash<Link, QList<Meta> > linkMetaDeleted)
{
    QHashIterator<Id, QList<Meta> > idIter(idMetaDeleted);
    while (idIter.hasNext()) {
        idIter.next();
        Link idLink;
        idLink.first = idIter.key();
        QList<Meta> deletedMetaList = idIter.value();
        updateSubscriptions(idLink, false, deletedMetaList, Meta::PublishDelete);
    }

    QHashIterator<Link, QList<Meta> > linkIter(linkMetaDeleted);
    while (linkIter.hasNext()) {
        linkIter.next();
        Link link = linkIter.key();
        QList<Meta> deletedMetaList = linkIter.value();
        updateSubscriptions(link,true, deletedMetaList, Meta::PublishDelete);
    }
}

// Iterate over all subscriptions for all publishers, checking and/or rebuilding
// the SearchGraphs.  If a subscription results in a changed SearchGraph that
// matches the subscription, build the appropriate metadata results, so that we
// can send out pollResults.
void Server::updateSubscriptions(Link link, bool isLink, QList<Meta> metaChanges, Meta::PublishOperationType publishType)
{
    const char *fnName = "Server::updateSubscriptions:";

    // An existing subscription becomes dirty in 3 cases:
    // 1. metadata is added to or removed from an identifier already in the SearchGraph
    //    --> In this case, we don't need to rebuild the SearchGraph
    // 2. metadata is added to a link already in the SearchGraph
    //    --> In this case, we don't need to rebuild the SearchGraph
    // 3. metadata is deleted from a link already in SearchGraph
    //    --> In this case we need to rebuild the SearchGraph if there is no more metadata on link
    // 4. metadata is added to or removed from a link which has one identifier
    //    already in the SearchGraph
    //    --> In this case we need to rebuild the SearchGraph, especially because a
    //        new link could link two separate sub-graphs together or a deleted link
    //        could prune a graph into two separate sub-graphs.

    QMutableHashIterator<QString,QList<SearchGraph> > allSubsIt(_subscriptionLists);
    while (allSubsIt.hasNext()) {
        allSubsIt.next();
        QString pubId = allSubsIt.key();
        QList<SearchGraph> subList = allSubsIt.value();
        if (_debug.testFlag(Server::ShowClientOps)) {
            qDebug() << fnName << "publisher:" << pubId << "has num subscriptions:" << subList.size();
        }

        bool publisherHasDirtySub = false;
        QMutableListIterator<SearchGraph> subIt(subList);
        while (subIt.hasNext()) {
            SearchGraph sub = subIt.next();
            if (_debug.testFlag(Server::ShowClientOps)) {
                qDebug() << fnName << "--checking subscription named:" << sub.name;
            }

            QSet<Id> idsWithConnectedGraphUpdates, idsWithConnectedGraphDeletes;
            QSet<Link> linksWithConnectedGraphUpdates, linksWithConnectedGraphDeletes;
            bool modifiedSearchGraph = false;
            bool subIsDirty = false;

            if (! isLink) {
                if (sub.idList.contains(link.first)) {
                    if (filteredMetadata(metaChanges, sub.resultFilter) > 0) {
                        // Case 1.
                        subIsDirty = true;
                        if (_debug.testFlag(Server::ShowClientOps)) {
                            qDebug() << fnName << "----subscription is dirty with existing id:" << link.first;
                        }
                    }
                }
            } else {
                if (sub.linkList.contains(link) && publishType == Meta::PublishDelete) {
                    if (filteredMetadata(metaChanges, sub.resultFilter) > 0) {
                        // Case 3.
                        subIsDirty = true;
                        if (_debug.testFlag(Server::ShowClientOps)) {
                            qDebug() << fnName << "----subscription is dirty deleting meta on existing link:" << link;
                        }
                    }
                }

                if (sub.linkList.contains(link) && publishType == Meta::PublishUpdate) {
                    if (filteredMetadata(metaChanges, sub.resultFilter) > 0) {
                        // Case 2.
                        subIsDirty = true;
                        if (_debug.testFlag(Server::ShowClientOps)) {
                            qDebug() << fnName << "----subscription is dirty updating meta on existing link:" << link;
                        }
                    }
                } else {
                    // Case 4.
                    QSet<Id> newIdList;
                    QSet<Link > newLinkList;
                    int currentDepth = -1;
                    buildSearchGraph(sub.startId, sub.matchLinks, sub.maxDepth, currentDepth, &newIdList, &newLinkList);

                    if (sub.idList != newIdList) {
                        subIsDirty = true;
                        modifiedSearchGraph = true;
                        // Metadata on these ids are in updateResults
                        idsWithConnectedGraphUpdates = newIdList - sub.idList;
                        // Metadata on these ids are in deleteResults
                        idsWithConnectedGraphDeletes = sub.idList - newIdList;

                        /*
                        QSetIterator<Id> idIt(idsWithConnectedGraphUpdates + idsWithConnectedGraphDeletes);
                        while (idIt.hasNext() && !(*operationError)) {
                            Id id = idIt.next();
                            QList<Meta> idMetaList = _mapGraph->metaForId(id);
                            if (filteredMetadata(idMetaList, sub.resultFilter, false) > 0) {
                                subIsDirty = true;
                                modifiedSearchGraph = true;
                            }
                        }
                        */

                        sub.idList = newIdList;
                        if (_debug.testFlag(Server::ShowClientOps)) {
                            qDebug() << fnName << "----subscription is dirty with newIdList.size:" << newIdList.size();
                        }
                    }

                    if (sub.linkList != newLinkList) {
                        subIsDirty = true;
                        modifiedSearchGraph = true;
                        // Metadata on these links are in updateResults
                        linksWithConnectedGraphUpdates = newLinkList - sub.linkList;
                        // Metadata on these links are in deleteResults
                        linksWithConnectedGraphDeletes = sub.linkList - newLinkList;

                        /*
                        QSetIterator<Link> linkIt(linksWithConnectedGraphUpdates + linksWithConnectedGraphDeletes);
                        while (linkIt.hasNext() && !sub.dirty) {
                            Link link = linkIt.next();
                            QList<Meta> linkMetaList = _mapGraph->metaForLink(link);
                            if (filteredMetadata(linkMetaList, sub.resultFilter, false) > 0) {
                                subIsDirty = true;
                                modifiedSearchGraph = true;
                            }
                        }
                        */

                        sub.linkList = newLinkList;
                        if (_debug.testFlag(Server::ShowClientOps)) {
                            qDebug() << fnName << "----subscription is dirty with newLinkList.size:" << newLinkList.size();
                        }
                    }
                }
            }

            if (subIsDirty && !sub.hasErrorResult) {
                // Construct results for the subscription
                QtSoapStruct *searchResult = 0, *errorResult = 0;
                // Build results from entire search graph for the poll response
                searchResult = new QtSoapStruct(QtSoapQName("searchResult"));
                searchResult->setAttribute("name", sub.name);

                IFMAP_ERRORCODES_1 addError = ::ErrorNone;
                int sSize = addSearchResultsWithResultFilter(searchResult, sub.maxSize, sub.matchLinks, sub.resultFilter, sub.idList, sub.linkList, &addError);
                sub.curSize += sSize;

                sub.response.insert(searchResult);

                // Check if we have exceeded our max size for the subscription
                if (sub.curSize > sub.maxSize) {
                    qDebug() << fnName << "Search results exceeded max-size with curSize:" << sub.curSize;
                    sub.hasErrorResult = true;

                    // TODO: Do I need to delete updateResult, deleteResult, searchResult, result?
                    sub.response.clear();

                    QString errString = Server::errorString(::IfmapPollResultsTooBig);
                    errorResult = new QtSoapStruct(QtSoapQName("errorResult"));
                    errorResult->setAttribute("errorCode",errString);
                    errorResult->setAttribute("name", sub.name);

                    sub.response.insert(errorResult);
                }

                subIt.setValue(sub);
                publisherHasDirtySub = true;
            }
        }

        if (publisherHasDirtySub) {
            allSubsIt.setValue(subList);
        }
    }
}

QtSoapStruct* Server::subResultForPollResult(Link link, bool isLink, SearchGraph *sub, QList<Meta> meta, Meta::PublishOperationType publishType)
{
    QtSoapStruct *result;
    QtSoapStruct *resultItem = new QtSoapStruct(QtSoapQName("resultItem"));

    QtSoapStruct *metaResult = new QtSoapStruct();
    /* TODO: I now interpret the search algorithm to say
       that link metadata returned from a search is first filtered by match-links.
       Then result-filter specifies _further_ rules for deleting data from the
       results.  I am only applying result-filter to _all_ metadata, and
       using match-links just for building the search graph.  In other words,
       match-links is a whitelist of link metadata and this interpretation of
       match-links keeps clients from discovering link metadata they do
       expect to exist.
    */
    int mSize = filteredMetadata(meta, sub->resultFilter, metaResult);

    if (mSize > 0) {
        resultItem->insert(metaResult);
        sub->curSize += mSize;
    } else {
        delete metaResult;
    }

    QtSoapType *idStruct1 = soapStructForId(link.first);
    QtSoapType *idStruct2 = (isLink ? soapStructForId(link.second) : 0);
    if (isLink) resultItem->insert(idStruct2);
    resultItem->insert(idStruct1);

    switch(publishType) {
    case Meta::PublishDelete:
        result = new QtSoapStruct(QtSoapQName("deleteResult"));
        break;
    case Meta::PublishUpdate:
        result = new QtSoapStruct(QtSoapQName("updateResult"));
        break;
    }

    result->setAttribute("name", sub->name);
    result->insert(resultItem);

    return result;
}

void Server::sendResultsOnActivePolls()
{
    // TODO: Often this slot gets signaled from a method that really only needs to
    // send results on active polls for a specific publisherId.  Could optimize
    // this slot in those cases.
    const char *fnName = "Server::sendResultsOnActivePolls:";
    QMutableHashIterator<QString,QList<SearchGraph> > allSubsIt(_subscriptionLists);
    while (allSubsIt.hasNext()) {
        allSubsIt.next();
        QString pubId = allSubsIt.key();        
        QList<SearchGraph> subList = allSubsIt.value();
        if (_debug.testFlag(Server::ShowClientOps)) {
            qDebug() << fnName << "publisher:" << pubId << "has num subscriptions:" << subList.size();
        }

        bool publisherHasErrorOnSub = false;
        bool sentPollToPublisher = false;
        QMutableListIterator<SearchGraph> subIt(subList);
        while (subIt.hasNext()) {
            SearchGraph sub = subIt.next();
            if (_debug.testFlag(Server::ShowClientOps)) {
                qDebug() << fnName << "--Checking subscription named:" << sub.name;
            }
            if (sub.curSize > 0 && _activePolls.contains(pubId)) {
                if (_debug.testFlag(Server::ShowClientOps)) {
                    qDebug() << fnName << "--Sending poll results for publisher with active poll:" << pubId;
                }
                QtSoapStruct *response = new QtSoapStruct(sub.response);
                sendResponse(_activePolls.value(pubId), soapResponseMsg(response));

                sub.response.clear();
                sub.curSize = 0;
                if (!sub.sentFirstResult) sub.sentFirstResult = true;
                if (sub.hasErrorResult) publisherHasErrorOnSub = true; // Mark for removing all subscriptions

                subIt.setValue(sub);
                sentPollToPublisher = true;
            }
        }

        if (publisherHasErrorOnSub) {
            allSubsIt.remove();
            qDebug() << fnName << "Removing subscriptions for publisherId:" << pubId;

            // We did send an errorResult
            _activePolls.remove(pubId);
        } else if (sentPollToPublisher) {
            // Update subscription list for this publisher
            allSubsIt.setValue(subList);
            _activePolls.remove(pubId);
        }
    }
}
