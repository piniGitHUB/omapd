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
#include <QXmlQuery>

#include "server.h"
#include "clientparser.h"
#include "mapsessions.h"
#include "mapresponse.h"

Server::Server(MapGraph *mapGraph, QObject *parent)
        : QTcpServer(parent), _mapGraph(mapGraph)
{
    const char *fnName = "Server::Server:";

    _omapdConfig = OmapdConfig::getInstance();
    _mapSessions = MapSessions::getInstance();

    if (_omapdConfig->valueFor("ifmap_ssl_configuration").toBool()) {
        QString ssl_proto = "AnyProtocol";
        if (_omapdConfig->isSet("ifmap_ssl_protocol")) {
            ssl_proto = _omapdConfig->valueFor("ifmap_ssl_protocol").toString();
        }
        if ( ( ssl_proto == "AnyProtocol") || ( ssl_proto == "NoSslV2" ) )
            this->_desiredSSLprotocol = QSsl::AnyProtocol;
        else if (ssl_proto == "SslV2")
            this->_desiredSSLprotocol = QSsl::SslV2;
        else if (ssl_proto == "SslV3")
            this->_desiredSSLprotocol = QSsl::SslV3;
        else if (ssl_proto == "TlsV1")
            this->_desiredSSLprotocol = QSsl::TlsV1;
        else
        { // If this else is reached - an invalid protocol was in the xml file
          qDebug() << "ifmap_ssl_protocol -- type invalid -- trying to continue "
                   << "using AnyProtocol";
          this->_desiredSSLprotocol = QSsl::AnyProtocol;
        }

        // Set server cert, private key, CRLs, etc.
        QString keyFileName = "server.key";
        QByteArray keyPassword = "";
        if (_omapdConfig->isSet("ifmap_private_key_file")) {
            keyFileName = _omapdConfig->valueFor("ifmap_private_key_file").toString();
            if (_omapdConfig->isSet("ifmap_private_key_password")) {
                keyPassword = _omapdConfig->valueFor("ifmap_private_key_password").toByteArray();
            }
        }
        QFile keyFile(keyFileName);
        // TODO: Add QSsl::Der format support from _omapdConfig
        // TODO: Add QSsl::Dsa support from _omapdConfig
        if (!keyFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            qDebug() << fnName << "No private key file:" << keyFile.fileName();
        } else {
            _serverKey = QSslKey(&keyFile, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey, keyPassword);
            qDebug() << fnName << "Loaded private key";
        }

        QString certFileName = "server.cert";
        // TODO: Add QSsl::Der format support from _omapdConfig
        if (_omapdConfig->isSet("ifmap_certificate_file")) {
            certFileName = _omapdConfig->valueFor("ifmap_certificate_file").toString();
        }
        QFile certFile(certFileName);
        if (!certFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            qDebug() << fnName << "No certificate file:" << certFile.fileName();
        } else {
            // Try PEM format fail over to DER; since they are the only 2
            // supported by the QSsl Certificate classes
            _serverCert = QSslCertificate(&certFile, QSsl::Pem);
            if ( _serverCert.isNull() )
                _serverCert = QSslCertificate(&certFile, QSsl::Der);

            qDebug() << fnName << "Loaded certificate with CN:" << _serverCert.subjectInfo(QSslCertificate::CommonName);
        }
        
        // Load server CAs
        if (_omapdConfig->isSet("ifmap_ca_certificates_file")) {
            QFile caFile(_omapdConfig->valueFor("ifmap_ca_certificates_file").toString());
            if (!caFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
                qDebug() << fnName << "No CA certificates file" << caFile.fileName();
            } else {
                _caCerts = QSslCertificate::fromDevice(&caFile, QSsl::Pem);
                qDebug() << fnName << "Loaded num CA certs:" << _caCerts.size();
            }
        }
    }

    QHostAddress listenOn;
    if (listenOn.setAddress(_omapdConfig->valueFor("ifmap_address").toString())) {
        unsigned int port = _omapdConfig->valueFor("ifmap_port").toUInt();

        if (listen(listenOn, port)) {
            this->setMaxPendingConnections(30); // 30 is QTcpServer default

            //connect(this, SIGNAL(newConnection()), this, SLOT(newClientConnection()));
            connect(this, SIGNAL(headerReceived(QTcpSocket*,QNetworkRequest)),
                    this, SLOT(processHeader(QTcpSocket*,QNetworkRequest)));

            connect(this, SIGNAL(clientRequestReceived(QTcpSocket*,MapRequest::RequestType,QVariant)),
                    this, SLOT(processClientRequest(QTcpSocket*,MapRequest::RequestType,QVariant)));

            connect(this, SIGNAL(checkActivePolls()),
                    this, SLOT(sendResultsOnActivePolls()));

            // Seed RNG for session-ids
            qsrand(QDateTime::currentDateTime().toTime_t());
        } else {
            qDebug() << fnName << "Error with listen on:" << listenOn.toString()
                    << ":" << port;
        }
    } else {
        qDebug() << fnName << "Error setting server address";
    }
}

void Server::incomingConnection(int socketDescriptor)
{
    const char *fnName = "Server::incomingConnection:";
    if (_omapdConfig->valueFor("ifmap_ssl_configuration").toBool()) {
        QSslSocket *sslSocket = new QSslSocket(this);
        if (sslSocket->setSocketDescriptor(socketDescriptor)) {

            sslSocket->setCiphers(QSslSocket::supportedCiphers());
            // TODO: Figure out how to just support QSsl::SslV3 & QSsl::TlsV1
            // QSsl::AnyProtocol accepts QSsl::SslV2 which is insecure
            sslSocket->setProtocol(this->_desiredSSLprotocol);

            // TODO: Have an option to set QSslSocket::setPeerVerifyDepth

            if (_omapdConfig->valueFor("ifmap_require_client_certificates").toBool()) {
                sslSocket->setPeerVerifyMode(QSslSocket::VerifyPeer);
            } else {
                // QueryPeer just asks for the client cert, but does not verify it
                sslSocket->setPeerVerifyMode(QSslSocket::QueryPeer);
            }

            // Connect SSL error signals to local slots
            connect(sslSocket, SIGNAL(peerVerifyError(QSslError)),
                    this, SLOT(clientSSLVerifyError(QSslError)));
            connect(sslSocket, SIGNAL(sslErrors(QList<QSslError>)),
                    this, SLOT(clientSSLErrors(QList<QSslError>)));

            sslSocket->setPrivateKey(_serverKey);
            sslSocket->setLocalCertificate(_serverCert);
            if (! _caCerts.isEmpty()) {
                sslSocket->setCaCertificates(_caCerts);
            }

            connect(sslSocket, SIGNAL(encrypted()), this, SLOT(socketReady()));

            sslSocket->startServerEncryption();
        } else {
            qDebug() << fnName << "Error setting SSL socket descriptor on QSslSocket";
            delete sslSocket;
        }
    } else {
        QTcpSocket *socket = new QTcpSocket(this);
        if (socket->setSocketDescriptor(socketDescriptor)) {
            connect(socket, SIGNAL(readyRead()), this, SLOT(readClient()));
            connect(socket, SIGNAL(disconnected()), this, SLOT(discardClient()));
            connect(socket, SIGNAL(stateChanged(QAbstractSocket::SocketState)),
                    this, SLOT(clientConnState(QAbstractSocket::SocketState)));
        } else {
            qDebug() << fnName << "Error setting socket descriptor on QTcpSocket";
            delete socket;
        }
    }
}

void Server::clientSSLVerifyError(const QSslError &error)
{
    const char *fnName = "Server::clientSSLVerifyError:";
    //QSslSocket *sslSocket = (QSslSocket *)sender();

    qDebug() << fnName << error.errorString();
}

void Server::clientSSLErrors(const QList<QSslError> &errors)
{
    const char *fnName = "Server::clientSSLErrors:";
    QSslSocket *sslSocket = (QSslSocket *)sender();

    foreach (const QSslError &error, errors) {
        qDebug() << fnName << error.errorString();
    }

    qDebug() << fnName << "Calling ignoreSslErrors";
    sslSocket->ignoreSslErrors();
}

void Server::socketReady()
{
    const char *fnName = "Server::socketReady:";
    QSslSocket *sslSocket = (QSslSocket *)sender();
    /// Do SSLV2 Checks
    if ( sslSocket->protocol() == QSsl::SslV2 ) {
        /// if we've got SSLV2 kill it if NoSslV2 was requested
        if ( _omapdConfig->isSet("ifmap_ssl_protocol") &&
         _omapdConfig->valueFor("ifmap_ssl_protocol").toString() == "NoSslV2") {
            /// Not explicity Requested - so shut it down
            qDebug() << fnName << "Disconnecting client - client is using SslV2 - NoSslV2 was requested in config ";
            sslSocket->disconnectFromHost();
            sslSocket->deleteLater();
            return;
        }
    }
    
    qDebug() << fnName << "Successful SSL handshake with peer:" << sslSocket->peerAddress().toString();

    bool clientAuthorized = false;

    if (_omapdConfig->valueFor("ifmap_require_client_certificates").toBool()) {
        clientAuthorized = authorizeClient(sslSocket);
    } else {
        qDebug() << fnName << "Client authorized because ifmap_require_client_certificates is false, for peer:"
                 << sslSocket->peerAddress().toString();
        clientAuthorized = true;
    }

    if (clientAuthorized) {
        connect(sslSocket, SIGNAL(readyRead()), this, SLOT(readClient()));
        connect(sslSocket, SIGNAL(disconnected()), this, SLOT(discardClient()));
        connect(sslSocket, SIGNAL(stateChanged(QAbstractSocket::SocketState)),
                this, SLOT(clientConnState(QAbstractSocket::SocketState)));
    } else {
        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps))
            qDebug() << fnName << "Disconnecting unauthorized client at:" << sslSocket->peerAddress().toString();
        sslSocket->disconnectFromHost();
        sslSocket->deleteLater();
    }
}

bool Server::authorizeClient(QSslSocket *sslSocket)
{
    const char *fnName = "Server::authorizeClient:";

    QList<QSslCertificate> clientCerts = sslSocket->peerCertificateChain();
    qDebug() << fnName << "Cert chain for client at:" << sslSocket->peerAddress().toString();
    for (int i=0; i<clientCerts.size(); i++) {
        qDebug() << fnName << "-- CN:" << clientCerts.at(i).subjectInfo(QSslCertificate::CommonName);
    }

    // TODO: add authorization and policy layer
    return true;
}

void Server::clientConnState(QAbstractSocket::SocketState sState)
{
    const char *fnName = "Server::clientConnState:";

    QTcpSocket* socket = (QTcpSocket*)sender();

    if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowHTTPState))
        qDebug() << fnName << "socket state for socket:" << socket
                 << "------------->:" << sState;

}

void Server::readClient()
{
    const char *fnName = "Server::readClient:";
    QTcpSocket* socket = (QTcpSocket*)sender();

    readHeader(socket);

    ClientParser clientParser;
    if (clientParser.read(socket)) {
        qDebug() << fnName << "Got request type:" << MapRequest::requestTypeString(clientParser.requestType())
                << "and IF-MAP version:" << MapRequest::requestVersionString(clientParser.requestVersion());

        if (clientParser.requestError()) {
            qDebug() << fnName << "Client Error:" << MapRequest::requestErrorString(clientParser.requestError());
        }
        emit clientRequestReceived(socket, clientParser.requestType(), clientParser.request());
    } else if (clientParser.requestError() != MapRequest::ErrorNone) {
        MapResponse errorResp(clientParser.requestVersion());
        if (clientParser.requestError() == MapRequest::IfmapClientSoapFault) {
            errorResp.setClientFault("No valid client request");
        } else {
            errorResp.setErrorResponse(clientParser.requestError(), clientParser.sessionId());
        }
        sendMapResponse(socket, errorResp);
    } else if (clientParser.error() != QXmlStreamReader::PrematureEndOfDocumentError){
        qDebug() << fnName << "XML Error reading client request:" << clientParser.errorString();
        MapResponse clientFaultResponse(MapRequest::VersionNone);
        clientFaultResponse.setClientFault(clientParser.errorString());
        sendMapResponse(socket, clientFaultResponse);
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

    if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowHTTPHeaders))
        qDebug() << fnName << "headerStr:" << endl << headerStr;

    return headerStr.length();
}

void Server::processHeader(QTcpSocket *socket, QNetworkRequest requestHdrs)
{
    const char *fnName = "Server::processHeader:";

    // TODO: Improve http protocol support
    if (requestHdrs.hasRawHeader(QByteArray("Expect"))) {
        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowHTTPHeaders))
            qDebug() << fnName << "Got Expect header";
        QByteArray expectValue = requestHdrs.rawHeader(QByteArray("Expect"));
        if (! expectValue.isEmpty() && expectValue.contains(QByteArray("100-continue"))) {
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowHTTPHeaders)) {
                qDebug() << fnName << "Got 100-continue Expect Header";
            }
            sendHttpResponse(socket, 100, "Continue");
        }
    }

    if (requestHdrs.hasRawHeader(QByteArray("Authorization"))) {
        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowHTTPHeaders))
            qDebug() << fnName << "Got Authorization header";
        QByteArray basicAuthValue = requestHdrs.rawHeader(QByteArray("Authorization"));
        if (! basicAuthValue.isEmpty() && basicAuthValue.contains(QByteArray("Basic"))) {
            basicAuthValue = basicAuthValue.mid(6);
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowHTTPHeaders)) {
                qDebug() << fnName << "Got Basic Auth value:" << basicAuthValue;
            }
            if (_omapdConfig->valueFor("ifmap_create_client_configurations").toBool()) {
                _mapSessions->registerClient(socket, QString(basicAuthValue));
            }
        }
    }
}

void Server::sendHttpResponse(QTcpSocket *socket, int hdrNumber, QString hdrText)
{
    const char *fnName = "Server::sendHttpResponse:";

    if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowHTTPHeaders)) {
        qDebug() << fnName << "Sending Http Response:" << hdrNumber << hdrText;
    }

    QHttpResponseHeader header(hdrNumber, hdrText);
    if (socket->state() == QAbstractSocket::ConnectedState) {
        socket->write(header.toString().toUtf8() );
    }
}

void Server::discardClient()
{
    QTcpSocket *socket = (QTcpSocket *)sender();

    // Remove socket from set of http headers received
    _headersReceived.remove(socket);

    _mapSessions->removeClientFromActivePolls(socket);

    // TODO: Set a timer to delete session metadata

    socket->deleteLater();
}

void Server::sendMapResponse(QTcpSocket *socket, MapResponse &mapResponse)
{
    const char *fnName = "Server::sendMapResponse:";

    QByteArray response = mapResponse.responseData();
    QHttpResponseHeader header(200,"OK");
    header.setContentType("text/xml");
    header.setContentLength(response.size());

    if (mapResponse.requestVersion() == MapRequest::IFMAPv11) {
        header.setValue("Server","omapd/ifmap1.1");
    }

    if (socket->state() == QAbstractSocket::ConnectedState) {
        socket->write(header.toString().toUtf8() );
        socket->write(response);

        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowHTTPHeaders))
            qDebug() << fnName << "Sent reply headers to client:" << endl << header.toString();

        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXML))
            qDebug() << fnName << "Sent reply to client:" << endl << response << endl;
    } else {
        qDebug() << fnName << "Socket is not connected!  Not sending reply to client";
    }
}

void Server::processClientRequest(QTcpSocket *socket, MapRequest::RequestType reqType, QVariant clientRequest)
{
    const char *fnName = "Server::processClientRequest:";

    MapResponse *clientFaultResponse;

    switch (reqType) {
    case MapRequest::RequestNone:
        // Error
        qDebug() << fnName << "No valid client request, will send SOAP Client Fault";
        clientFaultResponse = new MapResponse(MapRequest::VersionNone);
        clientFaultResponse->setClientFault("No valid client request");
        sendMapResponse(socket, *clientFaultResponse);
        break;
    case MapRequest::NewSession:
        processNewSession(socket, clientRequest);
        break;
    case MapRequest::AttachSession:
        processAttachSession(socket, clientRequest);
        break;
    case MapRequest::PurgePublisher:
        processPurgePublisher(socket, clientRequest);
        break;
    case MapRequest::Publish:
        processPublish(socket, clientRequest);
        break;
    case MapRequest::Subscribe:
        processSubscribe(socket, clientRequest);
        break;
    case MapRequest::Search:
        processSearch(socket, clientRequest);
        break;
    case MapRequest::Poll:
        processPoll(socket, clientRequest);
        break;
    }

}

void Server::processNewSession(QTcpSocket *socket, QVariant clientRequest)
{
    NewSessionRequest nsReq = clientRequest.value<NewSessionRequest>();
    QString publisherId = _mapSessions->assignPublisherId(socket);

    QString sessId;
    // Check if we have an SSRC session already for this publisherId
    if (_mapSessions->_activeSSRCSessions.contains(publisherId)) {
        sessId = _mapSessions->_activeSSRCSessions.value(publisherId);
        terminateSession(sessId);
    } else {
        QString sid;
        sid.setNum(qrand());
        QByteArray sidhash = QCryptographicHash::hash(sid.toAscii(), QCryptographicHash::Md5);
        sessId = QString(sidhash.toHex());
    }
    _mapSessions->_activeSSRCSessions.insert(publisherId, sessId);

    MapResponse nsResp(nsReq.requestVersion());
    nsResp.setNewSessionResponse(sessId, publisherId);
    sendMapResponse(socket, nsResp);
}

void Server::processAttachSession(QTcpSocket *socket, QVariant clientRequest)
{
    const char *fnName = "Server::processAttachSession:";
    AttachSessionRequest asReq = clientRequest.value<AttachSessionRequest>();
    MapResponse asResp(asReq.requestVersion());

    MapRequest::RequestError requestError = asReq.requestError();
    QString sessId = asReq.sessionId();
    QString publisherId = _mapSessions->_activeSSRCSessions.key(sessId);

    if (!requestError) {
        // Terminate any existing ARC sessions
        if (terminateARCSession(sessId)) {
            // If we had an existing ARC session, end the session
            terminateSession(sessId);
            requestError = MapRequest::IfmapInvalidSessionID;
            qDebug() << fnName << "Already have existing ARC session, terminating";
            asResp.setErrorResponse(requestError, sessId);
        } else {
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << fnName << "Adding ARC session for publisher:" << publisherId;
            }
            _mapSessions->_activeARCSessions.insert(publisherId, sessId);

            asResp.setAttachSessionResponse(sessId, publisherId);
        }
    } else {
        asResp.setErrorResponse(requestError, sessId);
    }

    sendMapResponse(socket, asResp);
}

void Server::processPublish(QTcpSocket *socket, QVariant clientRequest)
{
    const char *fnName = "Server::processPublish:";
    PublishRequest pubReq = clientRequest.value<PublishRequest>();

    MapRequest::RequestError requestError = pubReq.requestError();
    QString sessId = pubReq.sessionId();
    QString publisherId = _mapSessions->_activeSSRCSessions.key(sessId);

    bool mapGraphChanged = false;

    QList<PublishOperation> publishOperations = pubReq.publishOperations();
    QListIterator<PublishOperation> pubOperIt(publishOperations);
    while (pubOperIt.hasNext() && !requestError) {
        PublishOperation pubOper = pubOperIt.next();

        if (pubOper._publishType == PublishOperation::Update
            ) {

            if (pubOper._publishType == PublishOperation::Update) {
                _mapGraph->addMeta(pubOper._link, pubOper._isLink, pubOper._metadata, publisherId);
                mapGraphChanged = true;
                // update subscriptions
                updateSubscriptions(pubOper._link, pubOper._isLink, Meta::PublishUpdate);
            }
        } else if (pubOper._publishType == PublishOperation::Delete) {

            QList<Meta> existingMetaList;
            if (pubOper._isLink) existingMetaList = _mapGraph->metaForLink(pubOper._link);
            else existingMetaList = _mapGraph->metaForId(pubOper._link.first);

            bool metadataDeleted = false;

            QList<Meta> keepMetaList;
            QList<Meta> deleteMetaList;

            bool haveFilter = pubOper._clientSetDeleteFilter;

            if (! existingMetaList.isEmpty() && haveFilter) {
                QString filter = Subscription::translateFilter(pubOper._deleteFilter);

                QListIterator<Meta> metaListIt(existingMetaList);
                while (metaListIt.hasNext()) {
                    Meta aMeta = metaListIt.next();
                    /* First need to know if the delete filter will match anything,
                       because if it does match, then we'll need to notify any
                       active subscribers.
                    */
                    QString delMeta = filteredMetadata(aMeta, filter, pubOper._filterNamespaceDefinitions, requestError);
                    if (! requestError) {
                        if (delMeta.isEmpty()) {
                            // Keep this metadata (delete filter did not match)
                            keepMetaList.append(aMeta);
                            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                                qDebug() << fnName << "Found Meta to keep:" << aMeta.elementName();
                            }
                        } else {
                            deleteMetaList.append(aMeta);
                            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                                qDebug() << fnName << "Meta will be deleted:" << aMeta.elementName();
                            }
                            // Delete matched something, so this may affect subscriptions
                            metadataDeleted = true;
                        }
                    }
                }

                if (metadataDeleted) {
                    if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                        qDebug() << fnName << "Updating map graph because metadata was deleted";
                    }
                    _mapGraph->replaceMeta(pubOper._link, pubOper._isLink, keepMetaList);
                }

            } else if (! existingMetaList.isEmpty()) {
                // Default 3rd parameter on replaceMeta (empty QList) implies no meta to replace
                // No filter provided so we just delete all metadata
                _mapGraph->replaceMeta(pubOper._link, pubOper._isLink);
                metadataDeleted = true;
                deleteMetaList = existingMetaList;
            } else {
                if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                    qDebug() << fnName << "No metadata to delete!";
                }
            }

            if (metadataDeleted && !requestError) {
                mapGraphChanged = true;
                updateSubscriptions(pubOper._link, pubOper._isLink, Meta::PublishDelete);
            }

        }
    }

    // At this point all the publishes have occurred, we can check subscriptions
    if (requestError) {
        qDebug() << fnName << "Error in publish:" << MapRequest::requestErrorString(requestError);
    } else {
        emit checkActivePolls();
        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowMAPGraphAfterChange)) {
            _mapGraph->dumpMap();
        }
    }

    MapResponse pubResp(pubReq.requestVersion());
    if (requestError) {
        pubResp.setErrorResponse(requestError, sessId);
    } else {
        pubResp.setPublishResponse(sessId);
    }
    sendMapResponse(socket, pubResp);
}

void Server::processSubscribe(QTcpSocket *socket, QVariant clientRequest)
{
    const char *fnName = "Server::processSubscribe:";
    SubscribeRequest subReq = clientRequest.value<SubscribeRequest>();

    MapRequest::RequestError requestError = subReq.requestError();
    QString sessId = subReq.sessionId();
    QString publisherId = _mapSessions->_activeSSRCSessions.key(sessId);

    if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
        qDebug() << fnName << "Will manage subscriptions for publisher:" << publisherId;
    }

    QList<SubscribeOperation> subOperations = subReq.subscribeOperations();
    QListIterator<SubscribeOperation> subOperIt(subOperations);
    while (subOperIt.hasNext() && !requestError) {
        SubscribeOperation subOper = subOperIt.next();

        if (subOper.subscribeType() == SubscribeOperation::Update) {
            Subscription sub(subReq.requestVersion());
            sub._name = subOper.name();
            sub._search = subOper.search();
            int currentDepth = -1;
            buildSearchGraph(sub, sub._search.startId(), currentDepth);

            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << fnName << "Subscription:" << subOper.name();
                qDebug() << fnName << "    idList size:" << sub._idList.size();
                qDebug() << fnName << "    linkList size:" << sub._linkList.size();
            }

            QList<Subscription> subList = _mapSessions->_subscriptionLists.value(publisherId);
            if (subList.isEmpty()) {
                subList << sub;
            } else {
                // Replace any existing subscriptions with the same name
                subList.removeOne(sub);
                subList << sub;
            }
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << fnName << "subList size:" << subList.size();
            }

            _mapSessions->_subscriptionLists.insert(publisherId, subList);
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << fnName << "Adding SearchGraph to _subscriptionLists with name:" << sub._name;
            }

            if (_mapSessions->_activePolls.contains(publisherId)) {
                // signal to check subscriptions for polls
                emit checkActivePolls();
            }

        } else if (subOper.subscribeType() == SubscribeOperation::Delete) {
            Subscription delSub(subReq.requestVersion());
            delSub._name = subOper.name();

            QList<Subscription> subList = _mapSessions->_subscriptionLists.take(publisherId);
            if (! subList.isEmpty()) {
                subList.removeOne(delSub);
                if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                    qDebug() << fnName << "Removing subscription from subList with name:" << delSub._name;
                }
            } else {
                qDebug() << fnName << "No subscriptions to delete for publisher:" << publisherId;
            }

            if (! subList.isEmpty()) {
                _mapSessions->_subscriptionLists.insert(publisherId, subList);
            }

            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << fnName << "subList size:" << subList.size();
            }

        }
    }

    MapResponse subResp(subReq.requestVersion());
    if (requestError) {
        subResp.setErrorResponse(requestError, sessId);
    } else {
        subResp.setSubscribeResponse(sessId);
    }
    sendMapResponse(socket,subResp);
}

void Server::processSearch(QTcpSocket *socket, QVariant clientRequest)
{
    const char *fnName = "Server::processSearch:";
    SearchRequest searchReq = clientRequest.value<SearchRequest>();
    MapResponse searchResp(searchReq.requestVersion());

    MapRequest::RequestError requestError = searchReq.requestError();
    QString sessId = searchReq.sessionId();

    if (!requestError) {
        Subscription tempSub(searchReq.requestVersion());
        tempSub._search = searchReq.search();

        int currentDepth = -1;
        buildSearchGraph(tempSub, tempSub._search.startId(), currentDepth);

        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << fnName << "Search Lists";
            qDebug() << fnName << "    idList size:" << tempSub._idList.size();
            qDebug() << fnName << "    linkList size:" << tempSub._linkList.size();
        }

        collectSearchGraphMetadata(tempSub, SearchResult::SearchResultType, requestError);

        if (requestError != MapRequest::ErrorNone) {
            tempSub.clearSearchResults();
            searchResp.setErrorResponse(requestError, sessId);
        } else {
            searchResp.setSearchResults(sessId, tempSub._searchResults);
            tempSub.clearSearchResults();
        }
    } else {
        searchResp.setErrorResponse(requestError, searchReq.sessionId());
    }

    sendMapResponse(socket, searchResp);
}

void Server::processPurgePublisher(QTcpSocket *socket, QVariant clientRequest)
{
    const char *fnName = "Server::processPurgePublisher:";
    PurgePublisherRequest ppReq = clientRequest.value<PurgePublisherRequest>();

    MapRequest::RequestError requestError = ppReq.requestError();
    QString sessId = ppReq.sessionId();
    QString publisherId = _mapSessions->_activeSSRCSessions.key(sessId);

    if (!requestError) {
        QString purgePubId = ppReq.publisherId();
        if (purgePubId.compare(publisherId) != 0) {
            // TODO: Set configuration option for this
            requestError = MapRequest::IfmapAccessDenied;
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
                if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowMAPGraphAfterChange)) {
                    _mapGraph->dumpMap();
                }
            }
        }
    }

    MapResponse ppResp(ppReq.requestVersion());
    if (requestError) {
        ppResp.setErrorResponse(requestError, sessId);
    } else {
        ppResp.setPurgePublisherResponse(sessId);
    }
    sendMapResponse(socket,ppResp);
}

void Server::processPoll(QTcpSocket *socket, QVariant clientRequest)
{
    const char *fnName = "Server::processPoll:";
    PollRequest pollReq = clientRequest.value<PollRequest>();

    MapRequest::RequestError requestError = pollReq.requestError();
    QString sessId = pollReq.sessionId();
    QString publisherId = _mapSessions->_activeSSRCSessions.key(sessId);

    if (!requestError) {
        if (_mapSessions->_activeARCSessions.contains(publisherId) &&
            (pollReq.requestVersion() == MapRequest::IFMAPv11)) {
            // Track the TCP socket this publisher's poll is on
            _mapSessions->_activePolls.insert(publisherId, socket);

            if (_mapSessions->_subscriptionLists.value(publisherId).isEmpty()) {
                // No immediate client response
                if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                    qDebug() << fnName << "No subscriptions for publisherId:" << publisherId;
                }
            } else {
                emit checkActivePolls();
            }
        } else {
            // Error
            requestError = MapRequest::IfmapInvalidSessionID;
            qDebug() << fnName << "No active ARC session for poll from publisherId:" << publisherId;
        }
    }

    if (requestError) {
        if (_mapSessions->_subscriptionLists.contains(publisherId)) {
            _mapSessions->_subscriptionLists.remove(publisherId);
            qDebug() << fnName << "Removing subscriptions for publisherId:" << publisherId;
        }

        MapResponse pollErrorResponse(pollReq.requestVersion());
        pollErrorResponse.setErrorResponse(requestError, sessId);
        sendMapResponse(socket, pollErrorResponse);
    }
}

bool Server::terminateSession(QString sessionId)
{
    const char *fnName = "Server::terminateSession";
    bool hadExistingSession = false;

    // Remove sessionId from list of active SSRC Sessions
    QString publisherId = _mapSessions->_activeSSRCSessions.key(sessionId);

    if (! publisherId.isEmpty()) {
        hadExistingSession = true;

        _mapSessions->_activeSSRCSessions.remove(sessionId);

        if (_mapSessions->_subscriptionLists.contains(publisherId)) {
            _mapSessions->_subscriptionLists.remove(publisherId);
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
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
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowMAPGraphAfterChange)) {
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

    QString publisherId = _mapSessions->_activeARCSessions.key(sessionId);

    if (! publisherId.isEmpty()) {
        hadExistingARCSession = true;

        // End active ARC Session
        _mapSessions->_activeARCSessions.remove(publisherId);
        qDebug() << fnName << "Ending active ARC Session for publisherId:" << publisherId;

        // Terminate polls
        if (_mapSessions->_activePolls.contains(publisherId)) {
            _mapSessions->_activePolls.remove(publisherId);
            qDebug() << fnName << "Terminated active poll for publisherId:" << publisherId;
        }
    }

    return hadExistingARCSession;
}

QString Server::filteredMetadata(Meta meta, QString filter, QMap<QString, QString> searchNamespaces, MapRequest::RequestError &error)
{
    QList<Meta> singleMetaList;
    singleMetaList.append(meta);
    return filteredMetadata(singleMetaList, filter, searchNamespaces, error);
}

QString Server::filteredMetadata(QList<Meta>metaList, QString filter, QMap<QString, QString>searchNamespaces, MapRequest::RequestError &error)
{
    const char *fnName = "Server::filteredMetadata:";
    QString resultString("");
    bool matchAll = false;

    /* The filter will be either a match-links, result-filter, or delete filter,
       depending on where this method is called.  The "invert" parameter reverses the
       sense of the filter, so if the filter is a delete filter, be sure
       to set invert = true.
    */
    if (filter.isEmpty()) {
        qDebug() << fnName << "Empty filter string matches nothing";
        return resultString;
    } else if (filter == "*") {
        matchAll = true;
    }

    QString qString;
    QTextStream queryStream(&qString);

    if (!matchAll) {
        QMapIterator<QString, QString> nsIt(searchNamespaces);
        while (nsIt.hasNext()) {
            nsIt.next();
            queryStream << "declare namespace "
                    << nsIt.key()
                    << " = \""
                    << nsIt.value()
                    << "\";";
        }

        queryStream << "<metadata>";
    }

    QListIterator<Meta> metaIt(metaList);
    while (metaIt.hasNext()) {
        queryStream << metaIt.next().metaXML();
    }

    if (!matchAll) {
        queryStream << "</metadata>";
        queryStream << "//"
                    << filter;
    }

    if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLFilterStatements))
        qDebug() << fnName << "Query Statement:" << endl << qString;

    QXmlQuery query;
    bool qrc;

    if (!matchAll) {
        query.setQuery(qString);
        qrc = query.evaluateTo(&resultString);
    } else {
        resultString = qString;
        qrc = true;
    }

    // Make sure (resultString.size() == 0) is true for checking if we have results
    resultString = resultString.trimmed();

    if (! qrc) {
        qDebug() << fnName << "Error running query!";
        error = MapRequest::IfmapSystemError;
    } else {
        // If there are no query results, we won't add <metadata> enclosing element
        if (! resultString.isEmpty()) {
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLFilterResults))
                qDebug() << fnName << "Query Result:" << endl << resultString;

            resultString.prepend("<metadata>");
            resultString.append("</metadata>");
        }
    }

    return resultString;
}

void Server::addIdentifierResult(Subscription &sub, Identifier id, QList<Meta> metaList, SearchResult::ResultType resultType, MapRequest::RequestError &operationError)
{
    const char *fnName = "Server::addIdentifierResult:";

    SearchResult *searchResult = new SearchResult(resultType, SearchResult::IdentifierResult);
    searchResult->_id = id;

    if (!metaList.isEmpty()) {
        QString metaString = filteredMetadata(metaList, sub._search.resultFilter(), sub._search.filterNamespaceDefinitions(), operationError);

        if (! metaString.isEmpty()) {
            searchResult->_metadata = metaString;
            sub._curSize += metaString.size();
            if (sub._curSize > sub._search.maxSize()) {
                qDebug() << fnName << "Search results exceeded max-size with curSize;" << sub._curSize;
                operationError = MapRequest::IfmapSearchResultsTooBig;
                sub._subscriptionError = MapRequest::IfmapSearchResultsTooBig;
            }
        }
    }

    if (resultType == SearchResult::SearchResultType) {
        sub._searchResults.append(searchResult);
    }
}

void Server::addLinkResult(Subscription &sub, Link link, QList<Meta> metaList, SearchResult::ResultType resultType, MapRequest::RequestError &operationError)
{
    const char *fnName = "Server::addLinkResult:";

    SearchResult *searchResult = new SearchResult(resultType, SearchResult::LinkResult);
    searchResult->_link = link;

    if (!metaList.isEmpty()) {
        QString combinedFilter = Subscription::intersectFilter(sub._search.matchLinks(), sub._search.resultFilter());
        QString metaString = filteredMetadata(metaList, combinedFilter, sub._search.filterNamespaceDefinitions(), operationError);

        if (! metaString.isEmpty()) {
            searchResult->_metadata = metaString;
            sub._curSize += metaString.size();
            if (sub._curSize > sub._search.maxSize()) {
                qDebug() << fnName << "Search results exceeded max-size with curSize;" << sub._curSize;
                operationError = MapRequest::IfmapSearchResultsTooBig;
                sub._subscriptionError = MapRequest::IfmapSearchResultsTooBig;
            }
        }
    }

    if (resultType == SearchResult::SearchResultType) {
        sub._searchResults.append(searchResult);
    }
}

void Server::collectSearchGraphMetadata(Subscription &sub, SearchResult::ResultType resultType, MapRequest::RequestError &operationError)
{
    const char *fnName = "Server::collectSearchGraphMetadata:";

    QSetIterator<Id> idIt(sub._idList);
    while (idIt.hasNext() && !operationError) {
        Id id = idIt.next();
        QList<Meta> idMetaList = _mapGraph->metaForId(id);
        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << fnName << "idMetaList size for id:" << id << "-->" << idMetaList.size();
        }
        addIdentifierResult(sub, id, idMetaList, resultType, operationError);
    }

    QSetIterator<Link> linkIt(sub._linkList);
    while (linkIt.hasNext() && !operationError) {
        Link link = linkIt.next();
        QList<Meta> linkMetaList = _mapGraph->metaForLink(link);
        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << fnName << "linkMetaList size for link:" << link << "-->" << linkMetaList.size();
        }
        addLinkResult(sub, link, linkMetaList, resultType, operationError);
    }
}

// currentDepth is pass by value!  Must initially be -1.
void Server::buildSearchGraph(Subscription &sub, Id startId, int currentDepth)
{
    const char *fnName = "Server::buildSearchGraph";

    // 1. Current id, current results, current depth
    currentDepth++;
    if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
        qDebug() << fnName << "Starting identifier:" << startId;
        qDebug() << fnName << "Current depth:" << currentDepth;
    }

    // 2. Save current identifier in list of traversed identifiers
    // so we can later gather metadata from these identifiers.
    sub._idList.insert(startId);

    // 4. Check max depth reached
    if (currentDepth >= sub._search.maxDepth()) {
        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << fnName << "max depth reached:" << sub._search.maxDepth();
        }
        return;
    }

    // 5. Get list of links that have startId in link and pass matchLinks filter
    QSet<Link> linksWithCurId;
    QList<Id> startIdLinks = _mapGraph->linksTo(startId);
    QListIterator<Id> idIter(startIdLinks);
    while (idIter.hasNext()) {
        // TODO: performance increase by excluding the previous startId from this loop

        // matchId is the other end of the link
        Id matchId = idIter.next();
        // Get identifier-order independent link
        Link link = Identifier::makeLinkFromIds(startId, matchId);
        // Get metadata on this link
        QList<Meta> curLinkMeta = _mapGraph->metaForLink(link);
        //If any of this metadata matches matchLinks add link to idMatchList
        MapRequest::RequestError error = MapRequest::ErrorNone;
        QString matchLinkMeta = filteredMetadata(curLinkMeta, sub._search.matchLinks(), sub._search.filterNamespaceDefinitions(), error);
        if (! matchLinkMeta.isEmpty()) {
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << fnName << "Adding link:" << link;
            }
            linksWithCurId.insert(link);
        }
    }

    // Remove links we've already seen before
    linksWithCurId.subtract(sub._linkList);

    if (linksWithCurId.isEmpty()) {
        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << fnName << "linksWithCurId is empty!!!";
        }
        return;
    } else {
        // 6. Append subLinkList to linkList (unite removes repeats)
        sub._linkList.unite(linksWithCurId);

        // 7. Recurse
        QSetIterator<Link > linkIter(linksWithCurId);
        while (linkIter.hasNext()) {
            Link link = linkIter.next();
            Id linkedId = Identifier::otherIdForLink(link, startId);
            // linkedId becomes startId in recursion
            buildSearchGraph(sub, linkedId, currentDepth);
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
        updateSubscriptions(idLink, false, Meta::PublishDelete);
    }

    QHashIterator<Link, QList<Meta> > linkIter(linkMetaDeleted);
    while (linkIter.hasNext()) {
        linkIter.next();
        Link link = linkIter.key();
        updateSubscriptions(link,true, Meta::PublishDelete);
    }
}

// Iterate over all subscriptions for all publishers, checking and/or rebuilding
// the SearchGraphs.  If a subscription results in a changed SearchGraph that
// matches the subscription, build the appropriate metadata results, so that we
// can send out pollResults.
void Server::updateSubscriptions(Link link, bool isLink, Meta::PublishOperationType publishType)
{
    const char *fnName = "Server::updateSubscriptions:";

    // An existing subscription becomes dirty in 4 cases:
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

    QMutableHashIterator<QString,QList<Subscription> > allSubsIt(_mapSessions->_subscriptionLists);
    while (allSubsIt.hasNext()) {
        allSubsIt.next();
        QString pubId = allSubsIt.key();
        QList<Subscription> subList = allSubsIt.value();
        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << fnName << "publisher:" << pubId << "has num subscriptions:" << subList.size();
        }

        bool publisherHasDirtySub = false;
        QMutableListIterator<Subscription> subIt(subList);
        while (subIt.hasNext()) {
            Subscription sub = subIt.next();
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << fnName << "--checking subscription named:" << sub._name;
            }

            QSet<Id> idsWithConnectedGraphUpdates, idsWithConnectedGraphDeletes;
            QSet<Link> linksWithConnectedGraphUpdates, linksWithConnectedGraphDeletes;
            bool modifiedSearchGraph = false;
            bool subIsDirty = false;

            if (! isLink) {
                if (sub._idList.contains(link.first)) {
                    // Case 1.
                    subIsDirty = true;
                    if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                        qDebug() << fnName << "----subscription is dirty with id in SearchGraph:" << link.first;
                    }
                }
            } else {
                if (sub._linkList.contains(link) && publishType == Meta::PublishDelete) {
                    // Case 3.
                    subIsDirty = true;
                    if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                        qDebug() << fnName << "----subscription is dirty with link in SearchGraph:" << link;
                    }
                }

                if (sub._linkList.contains(link) && publishType == Meta::PublishUpdate) {
                    // Case 2.
                    subIsDirty = true;
                } else {
                    // Case 4. (and search graph rebuild for case 3)
                    QSet<Id> existingIdList = sub._idList;
                    QSet<Link> existingLinkList = sub._linkList;
                    sub._idList.clear();
                    sub._linkList.clear();
                    int currentDepth = -1;
                    buildSearchGraph(sub, sub._search.startId(), currentDepth);

                    if (sub._idList != existingIdList) {
                        subIsDirty = true;
                        modifiedSearchGraph = true;
                        // Metadata on these ids are in updateResults
                        idsWithConnectedGraphUpdates = sub._idList - existingIdList;
                        // Metadata on these ids are in deleteResults
                        idsWithConnectedGraphDeletes = existingIdList - sub._idList;

                        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                            qDebug() << fnName << "----subscription is dirty with newIdList.size:" << sub._idList.size();
                        }
                    }

                    if (sub._linkList != existingLinkList) {
                        subIsDirty = true;
                        modifiedSearchGraph = true;
                        // Metadata on these links are in updateResults
                        linksWithConnectedGraphUpdates = sub._linkList - existingLinkList;
                        // Metadata on these links are in deleteResults
                        linksWithConnectedGraphDeletes = existingLinkList - sub._linkList;

                        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                            qDebug() << fnName << "----subscription is dirty with newLinkList.size:" << sub._linkList.size();
                        }
                    }
                }
            }

            if (subIsDirty && !sub._subscriptionError) {
                // Construct results for the subscription
                if (sub._requestVersion == MapRequest::IFMAPv11) {
                    // Trigger to build and send pollResults
                    sub._sentFirstResult = false;
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

void Server::sendResultsOnActivePolls()
{
    // TODO: Often this slot gets signaled from a method that really only needs to
    // send results on active polls for a specific publisherId.  Could optimize
    // this slot in those cases.
    const char *fnName = "Server::sendResultsOnActivePolls:";
    QMutableHashIterator<QString,QList<Subscription> > allSubsIt(_mapSessions->_subscriptionLists);
    while (allSubsIt.hasNext()) {
        allSubsIt.next();
        QString pubId = allSubsIt.key();
        // Only check subscriptions for publisher if client has an active poll
        if (_mapSessions->_activePolls.contains(pubId)) {
            QList<Subscription> subList = allSubsIt.value();
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << fnName << "publisher:" << pubId << "has num subscriptions:" << subList.size();
            }

            bool publisherHasError = false;
            MapResponse *pollResponse = 0;
            MapRequest::RequestVersion pollResponseVersion = MapRequest::VersionNone;

            QMutableListIterator<Subscription> subIt(subList);
            while (subIt.hasNext()) {
                Subscription sub = subIt.next();

                MapRequest::RequestError subError = MapRequest::ErrorNone;
                if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                    qDebug() << fnName << "--Checking subscription named:" << sub._name;
                }

                if (pollResponseVersion == MapRequest::VersionNone) {
                    pollResponseVersion = sub._requestVersion;
                }

                if (sub._subscriptionError) {
                    if (!pollResponse) {
                        pollResponse = new MapResponse(pollResponseVersion);
                        pollResponse->startPollResponse(_mapSessions->_activeARCSessions.value(pubId));
                    }
                    pollResponse->addPollErrorResult(sub._name, sub._subscriptionError);

                    sub.clearSearchResults();
                    subIt.setValue(sub);
                } else if (!sub._sentFirstResult) {
                    // Build results from entire search graph for the first poll response
                    collectSearchGraphMetadata(sub, SearchResult::SearchResultType, subError);

                    if (subError) {
                        qDebug() << fnName << "Search results exceeded max-size with curSize:" << sub._curSize;
                        sub._subscriptionError = subError;
                        sub.clearSearchResults();
                        publisherHasError = true;

                        if (!pollResponse) {
                            pollResponse = new MapResponse(pollResponseVersion);
                            pollResponse->startPollResponse(_mapSessions->_activeARCSessions.value(pubId));
                        }
                        pollResponse->addPollErrorResult(sub._name, sub._subscriptionError);
                        subIt.setValue(sub);
                    } else if (sub._searchResults.count() > 0) {
                        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                            qDebug() << fnName << "--Gathering initial poll results for publisher with active poll:" << pubId;
                        }

                        if (!pollResponse) {
                            pollResponse = new MapResponse(pollResponseVersion);
                            pollResponse->startPollResponse(_mapSessions->_activeARCSessions.value(pubId));
                        }
                        pollResponse->addPollResults(sub._searchResults, sub._name);
                        sub.clearSearchResults();

                        sub._sentFirstResult = true;
                        subIt.setValue(sub);
                    } else {
                        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                            qDebug() << fnName << "--No results for subscription at this time";
                            qDebug() << fnName << "----_activePolls.contains(pubId):" << _mapSessions->_activePolls.contains(pubId);
                        }
                    }
                }
            }

            if (pollResponse) {
                if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps))
                    qDebug() << fnName << "Sending pollResults";
                pollResponse->endPollResponse();
                sendMapResponse(_mapSessions->_activePolls.value(pubId), *pollResponse);
                delete pollResponse;
                // Update subscription list for this publisher
                allSubsIt.setValue(subList);
                _mapSessions->_activePolls.remove(pubId);
            }

            if (publisherHasError) {

                _mapSessions->_activePolls.remove(pubId);
            }
        }
    }
}
