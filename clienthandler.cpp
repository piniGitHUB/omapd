/*
clienthandler.cpp: Implementation of ClientHandler class

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

#include <QHostAddress>
#include <QSslCipher>
#include <QNetworkRequest>
#include <QHttpResponseHeader>
#include <QXmlQuery>

#include "clienthandler.h"
#include "clientparser.h"
#include "mapsessions.h"
#include "clientconfiguration.h"

QString ClientHandler::buildDN(QSslCertificate cert, ClientHandler::CertInfoTarget target)
{
    QStringList dnElements;
    QString certDN;

    if (target == ClientHandler::Subject) {
        dnElements << cert.subjectInfo(QSslCertificate::Organization)
                << cert.subjectInfo(QSslCertificate::CountryName)
                << cert.subjectInfo(QSslCertificate::StateOrProvinceName)
                << cert.subjectInfo(QSslCertificate::LocalityName)
                << cert.subjectInfo(QSslCertificate::OrganizationalUnitName)
                << cert.subjectInfo(QSslCertificate::CommonName);
    } else if (target == ClientHandler::Issuer) {
        dnElements << cert.subjectInfo(QSslCertificate::Organization)
                << cert.issuerInfo(QSslCertificate::CountryName)
                << cert.issuerInfo(QSslCertificate::StateOrProvinceName)
                << cert.issuerInfo(QSslCertificate::LocalityName)
                << cert.issuerInfo(QSslCertificate::OrganizationalUnitName)
                << cert.issuerInfo(QSslCertificate::CommonName);
    }

    certDN = dnElements.join("/") + ":";
    return certDN;
}

ClientHandler::ClientHandler(MapGraphInterface *mapGraph, QObject *parent) :
    QSslSocket(parent), _mapGraph(mapGraph)
{
    _useCompression = false;

    _omapdConfig = OmapdConfig::getInstance();
    _mapSessions = MapSessions::getInstance();

    _authType = MapRequest::AuthNone;

    // Connect SSL error signals to local slots
    connect(this, SIGNAL(sslErrors(QList<QSslError>)),
            this, SLOT(clientSSLErrors(QList<QSslError>)));
    connect(this, SIGNAL(encrypted()), this, SLOT(socketReady()));

    _parser = new ClientParser(this);
    connect(_parser, SIGNAL(parsingComplete()),this, SLOT(handleParseComplete()));
    connect(_parser, SIGNAL(headerReceived(QNetworkRequest)),
            this, SLOT(processHeader(QNetworkRequest)));

}

ClientHandler::~ClientHandler()
{
    delete _parser;
}

void ClientHandler::socketReady()
{
    if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps))
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Successful SSL handshake with peer:" << this->peerAddress().toString();

    if (!this->sslConfiguration().peerCertificate().isNull())
        registerCert();

    connect(this, SIGNAL(readyRead()), this, SLOT(processReadyRead()));

    connect(this, SIGNAL(stateChanged(QAbstractSocket::SocketState)),
            this, SLOT(clientConnState(QAbstractSocket::SocketState)));
}

void ClientHandler::clientSSLErrors(const QList<QSslError> &errors)
{
    foreach (const QSslError &error, errors) {
        qDebug() << __PRETTY_FUNCTION__ << ":" << error.errorString();
    }

    if (errors.size() == 1 && errors.first().error() == QSslError::NoPeerCertificate) {
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Ignoring SSL Errors for No Peer Certificate";
        }
        this->ignoreSslErrors();
    }
}

void ClientHandler::registerCert()
{
    QSslCertificate clientCert = this->sslConfiguration().peerCertificate();

    _authType = MapRequest::AuthCert;
    _authToken = ClientHandler::buildDN(clientCert, ClientHandler::Subject);
    if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Cert for client at:" << this->peerAddress().toString();
        qDebug() << __PRETTY_FUNCTION__ << ":" << "-- DN:" << _authToken;
    }

    // If no existing MAP Client config for this client cert, give the client a chance with
    // CA-Cert umbrella clients
    if (_mapSessions->pubIdForAuthToken(_authToken).isEmpty()) {
        _authType = MapRequest::AuthCACert;
        _authToken = ClientHandler::buildDN(clientCert, ClientHandler::Issuer);
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Issuing Authority for client at:" << this->peerAddress().toString();
            qDebug() << __PRETTY_FUNCTION__ << ":" << "-- DN:" << _authToken;
        }
    }
}

void ClientHandler::clientConnState(QAbstractSocket::SocketState sState)
{
    if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowHTTPState))
        qDebug() << __PRETTY_FUNCTION__ << ":" << "socket state for socket:" << this
                 << "------------->:" << sState;
}

void ClientHandler::processHeader(QNetworkRequest requestHdrs)
{
    // TODO: Improve http protocol support
    if (requestHdrs.hasRawHeader(QByteArray("Expect"))) {
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowHTTPHeaders))
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Got Expect header";
        QByteArray expectValue = requestHdrs.rawHeader(QByteArray("Expect"));
        if (! expectValue.isEmpty() && expectValue.contains(QByteArray("100-continue"))) {
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowHTTPHeaders)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Got 100-continue Expect Header";
            }
            sendHttpResponse(100, "Continue");
        }
    }

    if (requestHdrs.hasRawHeader(QByteArray("Content-Length"))) {
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowHTTPHeaders))
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Got Content-Length header";
        bool ok = false;
        int contentLength = requestHdrs.rawHeader(QByteArray("Content-Length")).toInt(&ok);
        if (ok) {
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowHTTPHeaders)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Got Content-Length value:" << contentLength;
            }

        } else {
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowHTTPHeaders)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Error reading Content-Length header value";
            }
        }
    }

    if (requestHdrs.hasRawHeader(QByteArray("Authorization"))) {
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowHTTPHeaders))
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Got Authorization header";
        QByteArray basicAuthValue = requestHdrs.rawHeader(QByteArray("Authorization"));
        if (! basicAuthValue.isEmpty() && basicAuthValue.contains(QByteArray("Basic"))) {
            basicAuthValue = basicAuthValue.mid(6);
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowHTTPHeaders)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Got Basic Auth value:" << basicAuthValue;
            }
            // TODO: This will over write any AuthCert value since that happened earlier
            _authType = MapRequest::AuthBasic;
            // TODO: Don't use password as part of authToken
            _authToken = basicAuthValue;
        }
    }

    if (requestHdrs.hasRawHeader(QByteArray("Content-Encoding"))) {
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowHTTPHeaders))
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Got Content-Encoding header";
        QByteArray encodingValue = requestHdrs.rawHeader(QByteArray("Content-Encoding"));
        if (! encodingValue.isEmpty() && encodingValue.contains(QByteArray("gzip"))) {
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowHTTPHeaders)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Got Content-Encoding gzip";
            }
            _useCompression = true;
        }
    }

}

void ClientHandler::sendHttpResponse(int hdrNumber, QString hdrText)
{
    if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowRawSocketData))
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Sending Http Response:" << hdrNumber << hdrText;

    QHttpResponseHeader header(hdrNumber, hdrText);
    if (this->state() == QAbstractSocket::ConnectedState) {
        this->write(header.toString().toUtf8() );
    }
}

void ClientHandler::processReadyRead()
{
    if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps))
        qDebug() << __PRETTY_FUNCTION__ << ":" << "bytesAvailable:" << this->bytesAvailable() << "from peer:" << this->peerAddress().toString();

    if (this->isEncrypted()) {
        _parser->readData();
    } else {
        qDebug() << __PRETTY_FUNCTION__ << ":" << "NOT ENCRYPTED!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
    }
}

void ClientHandler::handleParseComplete()
{
    // Make sure we have something for clients that send no auth token
    if (_authType == MapRequest::AuthNone) {
        qDebug() << __PRETTY_FUNCTION__ << ":" << "No authentication from client";
        if (_omapdConfig->valueFor("allow_unauthenticated_clients").toBool()) {
            _authToken = this->peerAddress().toString();
            _authType = MapRequest::AuthAllowNone;
            qDebug() << __PRETTY_FUNCTION__ << ":" << "_authToken:" << _authToken;
        }
    }

    if (_parser->requestVersion() == MapRequest::VersionNone) {
        qDebug() << __PRETTY_FUNCTION__ << ":" << "XML Error reading client request:" << _parser->errorString();
        MapResponse clientFaultResponse(MapRequest::VersionNone);
        clientFaultResponse.setClientFault(_parser->errorString());
        sendMapResponse(clientFaultResponse);
    } else if (_parser->requestError() != MapRequest::ErrorNone) {
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Client Error:" << MapRequest::requestErrorString(_parser->requestError());

        MapResponse errorResp(_parser->requestVersion());
        if (_parser->requestError() == MapRequest::IfmapClientSoapFault) {
            errorResp.setClientFault(_parser->errorString());
        } else {
            errorResp.setErrorResponse(_parser->requestError(), _parser->sessionId());
        }
        sendMapResponse(errorResp);
    } else {
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps))
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Got request type:" << MapRequest::requestTypeString(_parser->requestType())
                     << "and IF-MAP version:" << MapRequest::requestVersionString(_parser->requestVersion());

        bool sentError = false;
        if (_parser->requestType() != MapRequest::NewSession) {
            // Validate session-id belongs to this client
            if (! _mapSessions->validateSessionId(_parser->sessionId(), _authToken)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "ERROR: Invalid session-id from pubId:"
                        << _mapSessions->pubIdForAuthToken(_authToken)
                        << "with session-id:" << _parser->sessionId();
                MapResponse errorResp(_parser->requestVersion());
                errorResp.setErrorResponse(MapRequest::IfmapInvalidSessionID, _parser->sessionId());
                sendMapResponse(errorResp);
                sentError = true;
            }
        }

        if (_parser->requestType() != MapRequest::NewSession &&
            _parser->requestType() != MapRequest::Poll &&
            !(_parser->requestVersion() == MapRequest::IFMAPv11 && _parser->requestType() == MapRequest::AttachSession)) {
            // Don't allow SSRC requests on ARC, other than NewSession
            if (_mapSessions->haveActiveARCForClient(_authToken) &&
                _mapSessions->ssrcForClient(_authToken) != this &&
                _mapSessions->arcForClient(_authToken) == this &&
                !sentError) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "ERROR: Received SSRC request ARC for pubId:" << _mapSessions->pubIdForAuthToken(_authToken);
                MapResponse errorResp(_parser->requestVersion());
                errorResp.setErrorResponse(MapRequest::IfmapInvalidSessionID, _parser->sessionId());
                sendMapResponse(errorResp);
                sentError = true;
            }

            // If SSRC request comes in on different connection, swap connections
            if (_mapSessions->haveActiveSSRCForClient(_authToken) &&
                _mapSessions->ssrcForClient(_authToken) != this &&
                !sentError) {
                if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                    qDebug() << __PRETTY_FUNCTION__ << ":" << "Servicing client on new SSRC.  Old:" << _mapSessions->ssrcForClient(_authToken)
                            << "New:" << this << "for pubId:" << _mapSessions->pubIdForAuthToken(_authToken);
                }
                _mapSessions->migrateSSRCForClient(_authToken, this);
            }
        }

        if (!sentError) processClientRequest();
    }

    delete _parser;
    _parser = new ClientParser(this);
    connect(_parser, SIGNAL(parsingComplete()),this, SLOT(handleParseComplete()));
    connect(_parser, SIGNAL(headerReceived(QNetworkRequest)),
            this, SLOT(processHeader(QNetworkRequest)));
}

void ClientHandler::sendPollResponse(QByteArray response, MapRequest::RequestVersion reqVersion)
{
    this->sendResponse(response, reqVersion);
}

void ClientHandler::sendMapResponse(MapResponse &mapResponse)
{
    this->sendResponse(mapResponse.responseData(), mapResponse.requestVersion());
}

void ClientHandler::sendResponse(QByteArray response, MapRequest::RequestVersion reqVersion)
{
    QByteArray compResponse;
    QHttpResponseHeader header(200,"OK");
    if (_useCompression) {
        compResponse = compressResponse(response);
        header.setValue("Content-Encoding", "gzip");
        header.setValue("Transfer-Encoding","chunked");
        header.setContentLength(compResponse.size());
    } else {
        header.setContentLength(response.size());
    }

    if (reqVersion == MapRequest::IFMAPv11) {
        header.setContentType("text/xml");
        header.setValue("Server","omapd/ifmap1.1");
    } else if (reqVersion == MapRequest::IFMAPv20) {
        header.setContentType("application/soap+xml");
        header.setValue("Server","omapd/ifmap2.0");
    }

    if (this->state() == QAbstractSocket::ConnectedState) {
        this->write(header.toString().toUtf8() );
        if (_useCompression) {
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowHTTPHeaders))
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Sending compressed response to client";
            this->write(compResponse);
        } else {
            this->write(response);
        }

        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowHTTPHeaders))
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Sent reply headers to client:" << endl << header.toString();

        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXML))
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Sent reply to client:" << endl << response << endl;
    } else {
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Socket is not connected!  Not sending reply to client";
    }
}

QByteArray ClientHandler::compressResponse(QByteArray uncompressed)
{
    QByteArray deflated;

    deflated = qCompress(uncompressed);

    // eliminate qCompress size on first 4 bytes and 2 byte header
    deflated = deflated.right(deflated.size() - 6);
    // remove qCompress 4 byte footer
    deflated = deflated.left(deflated.size() - 4);

    QByteArray header;
    header.resize(10);
    header[0] = 0x1f; // gzip-magic[0]
    header[1] = 0x8b; // gzip-magic[1]
    header[2] = 0x08; // Compression method = DEFLATE
    header[3] = 0x00; // Flags
    header[4] = 0x00; // 4-7 is mtime
    header[5] = 0x00;
    header[6] = 0x00;
    header[7] = 0x00;
    header[8] = 0x00; // XFL
    header[9] = 0x03; // OS=Unix

    deflated.prepend(header);

    QByteArray footer;
    quint32 crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, (const uchar*)uncompressed.data(), uncompressed.size());
    footer.resize(8);
    footer[3] = (crc & 0xff000000) >> 24;
    footer[2] = (crc & 0x00ff0000) >> 16;
    footer[1] = (crc & 0x0000ff00) >> 8;
    footer[0] = (crc & 0x000000ff);

    quint32 isize = uncompressed.size();
    footer[7] = (isize & 0xff000000) >> 24;
    footer[6] = (isize & 0x00ff0000) >> 16;
    footer[5] = (isize & 0x0000ff00) >> 8;
    footer[4] = (isize & 0x000000ff);

    deflated.append(footer);

    return deflated;
}

void ClientHandler::processClientRequest()
{
    MapRequest::RequestType reqType = _parser->requestType();
    QVariant clientRequest = _parser->request();

    MapResponse *clientFaultResponse;

    switch (reqType) {
    case MapRequest::RequestNone:
        // Error
        qDebug() << __PRETTY_FUNCTION__ << ":" << "No valid client request, will send SOAP Client Fault";
        clientFaultResponse = new MapResponse(MapRequest::VersionNone);
        clientFaultResponse->setClientFault("No valid client request");
        sendMapResponse(*clientFaultResponse);
        delete clientFaultResponse;
        break;
    case MapRequest::NewSession:
        processNewSession(clientRequest);
        break;
    case MapRequest::AttachSession:
        processAttachSession(clientRequest);
        break;
    case MapRequest::RenewSession:
        processRenewSession(clientRequest);
        break;
    case MapRequest::EndSession:
        processEndSession(clientRequest);
        break;
    case MapRequest::PurgePublisher:
        processPurgePublisher(clientRequest);
        break;
    case MapRequest::Publish:
        processPublish(clientRequest);
        break;
    case MapRequest::Subscribe:
        processSubscribe(clientRequest);
        break;
    case MapRequest::Search:
        processSearch(clientRequest);
        break;
    case MapRequest::Poll:
        processPoll(clientRequest);
        break;
    }

}

void ClientHandler::processNewSession(QVariant clientRequest)
{
    NewSessionRequest nsReq = clientRequest.value<NewSessionRequest>();
    MapResponse nsResp(nsReq.requestVersion());

    MapRequest::RequestError requestError = nsReq.requestError();

    nsReq.setAuthType(_authType);
    nsReq.setAuthValue(_authToken);

    QString publisherId = _mapSessions->registerMapClient(this, _authType, _authToken);
    if (publisherId.isEmpty()) {
        requestError = MapRequest::IfmapAccessDenied;
    }

    if (!requestError) {
        QString sessId;
        // Check if we have an SSRC session already for this publisherId
        if (_mapSessions->haveActiveSSRCForClient(_authToken)) {
            /* Per IFMAP20: 4.3: If a MAP Client sends more than one SOAP request
               containing a newSession element in the SOAP body, the MAP Server
               MUST respond by ending the previous session and starting a new
               session. The new session MAY use the same session-id or allocate a
               new one.
            */
            sessId = _mapSessions->sessIdForClient(_authToken);
            terminateSession(sessId, nsReq.requestVersion());
        }
        sessId = _mapSessions->addActiveSSRCForClient(_authToken);
        nsResp.setNewSessionResponse(sessId, publisherId, nsReq.clientSetMaxPollResultSize(), nsReq.maxPollResultSize());
    } else {
        nsResp.setErrorResponse(requestError, "");
    }

    sendMapResponse(nsResp);
}

void ClientHandler::processRenewSession(QVariant clientRequest)
{
    /* IFMAP20: 4.4: In order to keep an IF-MAP session from timing out,
       a MAP Client MUST either keep the underlying TCP connection associated
       with the SSRC open, or send periodic renewSession requests to the MAP Server.
    */
    RenewSessionRequest rsReq = clientRequest.value<RenewSessionRequest>();
    MapRequest::RequestError requestError = rsReq.requestError();
    QString sessId = rsReq.sessionId();

    MapResponse rsResp(rsReq.requestVersion());
    if (requestError) {
        rsResp.setErrorResponse(requestError, sessId);
    } else {
        rsResp.setRenewSessionResponse(sessId);
    }
    sendMapResponse(rsResp);
}

void ClientHandler::processEndSession(QVariant clientRequest)
{
    EndSessionRequest esReq = clientRequest.value<EndSessionRequest>();

    MapRequest::RequestError requestError = esReq.requestError();
    QString sessId = esReq.sessionId();

    MapResponse esResp(esReq.requestVersion());
    if (requestError) {
        esResp.setErrorResponse(requestError, sessId);
    } else {
        QString publisherId = _mapSessions->pubIdForAuthToken(_authToken);
        terminateSession(sessId, esReq.requestVersion());
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Terminated session-id:" << sessId
                     << "for publisher-id:" << publisherId;
        }
        esResp.setEndSessionResponse(sessId);
    }

    sendMapResponse(esResp);
}

void ClientHandler::processAttachSession(QVariant clientRequest)
{
    AttachSessionRequest asReq = clientRequest.value<AttachSessionRequest>();
    MapResponse asResp(asReq.requestVersion());

    /* IFMAP20: 4.3
    If a MAP Server receives a message containing a SOAP body containing an attachSession
    element that specifies a session which already has an ARC with an outstanding poll request, the
    MAP Server MUST:
         end the session
         respond to the poll request on the older ARC with an endSessionResult
         respond to the attachSession request on the newer ARC with an errorResult response
           with an errorCode of InvalidSessionID
    */

    MapRequest::RequestError requestError = asReq.requestError();
    QString sessId = asReq.sessionId();
    QString publisherId = _mapSessions->pubIdForAuthToken(_authToken);

    if (!requestError) {
        if (_mapSessions->ssrcForClient(_authToken) == this) {
            if (_omapdConfig->valueFor("allow_unauthenticated_clients").toBool()) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "NON-STANDARD: Allowing ARC on SSRC for pubId:" << publisherId;
            } else {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Error: Received poll request on SSRC for pubId:" << publisherId;
                requestError = MapRequest::IfmapInvalidSessionID;
                terminateSession(sessId, asReq.requestVersion());
            }
        } else if (terminateARCSession(sessId, asReq.requestVersion())) {
            // If we had an existing ARC session, end the session
            terminateSession(sessId, asReq.requestVersion());
            requestError = MapRequest::IfmapInvalidSessionID;
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Already have existing ARC session, terminating";
            asResp.setErrorResponse(requestError, sessId);
        } else {
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Adding ARC session for publisher:" << publisherId;
            }
            _mapSessions->setActiveARCForClient(_authToken, this);

            asResp.setAttachSessionResponse(sessId, publisherId);
        }
    }

    if (requestError) {
        asResp.setErrorResponse(requestError, sessId);
    }

    sendMapResponse(asResp);
}

// FIXME: This method attempts to deal with publish atomicity in a rather backhanded
// fashion.  I believe the map graph should be used rather than flattening
// the operations as is done in this method.  However, using the map graph would
// require a significant re-write of some fairly complex code for collecting
// intermediate subscription results.  Still it should be done at some point.
// Also to consider is atomicity for publishing multiple multiValue metadata
// items within a single publish request.
void ClientHandler::checkPublishAtomicity(PublishRequest &pubReq, MapRequest::RequestError &requestError)
{
    QList<PublishOperation> publishOperations = pubReq.publishOperations();
    QMutableListIterator<PublishOperation> pubOperIt(publishOperations);
    while (pubOperIt.hasNext()) {
        PublishOperation pubOperCheck = pubOperIt.next();

        // Only check operations that come later in the request against the current one
        for (int i=pubOperCheck._operationNumber; i<publishOperations.size(); i++) {
            PublishOperation pubOperTest = publishOperations[i];

            // Only examine publish operations on the same link or identifier
            // and these aren't the same operations within the publish request
            if (pubOperCheck._link == pubOperTest._link) {

                /* Check these cases:
                   1. If both publish operations are update
                      --> then remove duplicate metadata from pubOperCheck and if
                          pubOperCheck has no metadata left, remove it from request
                   2. If pubOperCheck is update and pubOperTest is delete
                      --> then apply delete filter to pubOperCheck's metadata
                   3. If both publish operations are delete
                      --> then if the delete filter is identical, remove pubOperCheck
                          from publish request
                   4. If both publish operations are notify
                      --> then noop, because notify doesn't have the same atomicity rules
                   5. If pubOperCheck is delete and pubOperTest is update
                      --> then noop, because this will be caught when the situation is reversed
                */
                if (pubOperCheck._publishType == PublishOperation::Update &&
                    pubOperTest._publishType == PublishOperation::Update) {
                    // 1.
                    QList<Meta> existingMetaList = pubOperCheck._metadata;
                    QList<Meta> metaTestList = pubOperTest._metadata;
                    QList<Meta> keepMetaList;

                    // TODO: Does this apply to multi-value metadata?
                    for (int i=0; i<existingMetaList.size(); i++) {
                        for (int j=0; j<metaTestList.size(); j++) {
                            // Consider adding here: && existingMetaList[i].cardinality() == Meta::SingleValue
                            if (existingMetaList[i] == metaTestList[j]) {
                                // dont keep
                                if (existingMetaList[i].cardinality() == Meta::MultiValue) {
                                    qDebug() << __PRETTY_FUNCTION__ << ":" << "ALERT: Publish atomicity eliminates multiValue metadata on"
                                            << (pubOperCheck._isLink ? "link:" : "id:")
                                            << pubOperCheck._link
                                            << "of type:" << existingMetaList[i].elementName()
                                            << "in namespace:" << existingMetaList[i].elementNS();
                                }
                            } else {
                                keepMetaList << existingMetaList[i];
                            }
                        }
                    }
                    if (keepMetaList.size() == 0) {
                        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                            qDebug() << __PRETTY_FUNCTION__ << ":" << "Publish atomicity eliminates update operation with duplicate metadata on"
                                    << (pubOperCheck._isLink ? "link:" : "id:")
                                    << pubOperCheck._link;
                        }
                        pubOperIt.remove();
                    } else if (keepMetaList.size() != existingMetaList.size()) {
                        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                            qDebug() << __PRETTY_FUNCTION__ << ":" << "Publish atomicity reduces duplicate metadata in update operation on"
                                    << (pubOperCheck._isLink ? "link:" : "id:")
                                    << pubOperCheck._link
                                    << "to number of metadata elements:" << keepMetaList.size();
                        }
                        pubOperCheck._metadata = keepMetaList;
                        pubOperIt.setValue(pubOperCheck);
                    }

                } else if (pubOperCheck._publishType == PublishOperation::Update &&
                           pubOperTest._publishType == PublishOperation::Delete) {

                    // 2.
                    QList<Meta> existingMetaList = pubOperCheck._metadata;
                    bool haveFilter = pubOperTest._clientSetDeleteFilter;

                    if (!existingMetaList.isEmpty() && haveFilter) {
                        bool metadataDeleted = false;
                        QPair< QList<Meta>, QList<Meta> > results = applyDeleteFilterToMeta(existingMetaList, pubOperTest, requestError, &metadataDeleted);
                        if (metadataDeleted) {

                            QList<Meta> keepMetaList = results.first;
                            if (keepMetaList.isEmpty()) {
                                if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                                    qDebug() << __PRETTY_FUNCTION__ << ":" << "Publish atomicity eliminates update operation on"
                                            << (pubOperCheck._isLink ? "link:" : "id:")
                                            << pubOperCheck._link
                                            << "with delete filter:" << pubOperTest._deleteFilter;
                                }
                                pubOperIt.remove();
                            } else {
                                if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                                    qDebug() << __PRETTY_FUNCTION__ << ":" << "Publish atomicity reduces update operation on"
                                            << (pubOperCheck._isLink ? "link:" : "id:")
                                            << pubOperCheck._link
                                            << "with delete filter:" << pubOperTest._deleteFilter
                                            << "to number of metadata elements:" << keepMetaList.size();
                                }
                                pubOperCheck._metadata = keepMetaList;
                                pubOperIt.setValue(pubOperCheck);
                            }
                        }

                    } else if (!existingMetaList.isEmpty()) {
                        // No delete filter provided, so we delete all metadata, thus eliminating pubOperCheck
                        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                            qDebug() << __PRETTY_FUNCTION__ << ":" << "Publish atomicity eliminates update operation on"
                                    << (pubOperCheck._isLink ? "link:" : "id:")
                                    << pubOperCheck._link
                                    << "with no filter:";
                        }
                        pubOperIt.remove();
                    }


                } else if (pubOperCheck._publishType == PublishOperation::Delete &&
                           pubOperTest._publishType == PublishOperation::Delete) {
                    // 3.
                    if (pubOperCheck._deleteFilter.compare(pubOperTest._deleteFilter, Qt::CaseSensitive) == 0) {
                        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                            qDebug() << __PRETTY_FUNCTION__ << ":" << "Publish atomicity eliminates duplicate delete operation on"
                                    << (pubOperCheck._isLink ? "link:" : "id:")
                                    << pubOperCheck._link
                                    << (pubOperCheck._clientSetDeleteFilter ? "with filter:" : "with no filter")
                                    << (pubOperCheck._clientSetDeleteFilter ? pubOperCheck._deleteFilter : "");
                        }
                        pubOperIt.remove();
                    }
                }
            }
        }
    }
    pubReq.setPublishOperations(publishOperations);
}

void ClientHandler::processPublish(QVariant clientRequest)
{
    PublishRequest pubReq = clientRequest.value<PublishRequest>();

    MapRequest::RequestError requestError = pubReq.requestError();
    QString sessId = pubReq.sessionId();
    QString publisherId = _mapSessions->pubIdForAuthToken(_authToken);

    checkPublishAtomicity(pubReq, requestError);

    bool mapGraphChanged = false;

    /* IFMAP20: 3.7.1:
       A successful metadata publish MUST result in a publishReceived message. Otherwise,
       the entire publish request MUST fail without effect and the response MUST contain
       an errorResult element with an errorCode attribute indicating the cause of the
       failure.
    */
    QList<PublishOperation> publishOperations = pubReq.publishOperations();
    QListIterator<PublishOperation> pubOperIt(publishOperations);
    while (pubOperIt.hasNext() && !requestError) {
        PublishOperation pubOper = pubOperIt.next();

        if (pubOper._publishType == PublishOperation::Update
            || pubOper._publishType == PublishOperation::Notify) {

            if (pubOper._publishType == PublishOperation::Update) {
                _mapGraph->addMeta(pubOper._link, pubOper._isLink, pubOper._metadata, publisherId);
                mapGraphChanged = true;
                // TODO: Move this outside of while loop for major performance boost!
                // update subscriptions
                updateSubscriptions(pubOper._link, pubOper._isLink, pubOper._metadata, Meta::PublishUpdate);
            } else if (pubOper._publishType == PublishOperation::Notify) {
                // Deal with notify
                updateSubscriptionsWithNotify(pubOper._link, pubOper._isLink, pubOper._metadata);
            }
        } else if (pubOper._publishType == PublishOperation::Delete) {

            QList<Meta> existingMetaList;
            if (pubOper._isLink) existingMetaList = _mapGraph->metaForLink(pubOper._link);
            else existingMetaList = _mapGraph->metaForId(pubOper._link.first);

            bool metadataDeleted = false;

            QList<Meta> keepMetaList;
            QList<Meta> deleteMetaList;

            bool haveFilter = pubOper._clientSetDeleteFilter;

            if (!existingMetaList.isEmpty() && haveFilter) {

                QPair< QList<Meta>, QList<Meta> > results = applyDeleteFilterToMeta(existingMetaList, pubOper, requestError, &metadataDeleted);
                keepMetaList = results.first;
                deleteMetaList = results.second;

                if (metadataDeleted) {
                    if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                        qDebug() << __PRETTY_FUNCTION__ << ":" << "Updating map graph because metadata was deleted";
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
                if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                    qDebug() << __PRETTY_FUNCTION__ << ":" << "No metadata to delete!";
                }
            }

            if (metadataDeleted && !requestError) {
                mapGraphChanged = true;
                updateSubscriptions(pubOper._link, pubOper._isLink, deleteMetaList, Meta::PublishDelete);
            }

        }
    }

    // Per IFMAP20: 3.7.1.4: The entire publish operation
    // MUST appear atomic to other clients.  So if multiple sub-operations, they need
    // to ALL be applied before any other search is allowed, or subscriptions matched.

    // At this point all the publishes have occurred, we can check subscriptions
    if (requestError) {
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Error in publish:" << MapRequest::requestErrorString(requestError);
    } else {
        sendResultsOnActivePolls();
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowMAPGraphAfterChange)) {
            _mapGraph->dumpMap();
        }
    }

    MapResponse pubResp(pubReq.requestVersion());
    if (requestError) {
        pubResp.setErrorResponse(requestError, sessId);
    } else {
        pubResp.setPublishResponse(sessId);
    }
    sendMapResponse(pubResp);
}

QPair< QList<Meta>, QList<Meta> > ClientHandler::applyDeleteFilterToMeta(QList<Meta> existingMetaList, PublishOperation pubOper, MapRequest::RequestError &requestError, bool *metadataDeleted)
{
    QList<Meta> keepMetaList;
    QList<Meta> deleteMetaList;

    QPair< QList<Meta>, QList<Meta> > result;

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
                if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                    qDebug() << __PRETTY_FUNCTION__ << ":" << "Found Meta to keep:" << aMeta.elementName();
                }
            } else {
                deleteMetaList.append(aMeta);
                if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                    qDebug() << __PRETTY_FUNCTION__ << ":" << "Meta will be deleted:" << aMeta.elementName();
                }
                // Delete matched something, so this may affect subscriptions
                *metadataDeleted = true;
            }
        }
    }

    result.first = keepMetaList;
    result.second = deleteMetaList;
    return result;

}

void ClientHandler::processSubscribe(QVariant clientRequest)
{
    SubscribeRequest subReq = clientRequest.value<SubscribeRequest>();

    MapRequest::RequestError requestError = subReq.requestError();
    QString sessId = subReq.sessionId();
    QString publisherId = _mapSessions->pubIdForAuthToken(_authToken);

    if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Will manage subscriptions for publisher:" << publisherId;
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

            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Subscription:" << subOper.name();
                qDebug() << __PRETTY_FUNCTION__ << ":" << "    idList size:" << sub._idList.size();
                qDebug() << __PRETTY_FUNCTION__ << ":" << "    linkList size:" << sub._linkList.size();
            }

            QList<Subscription> subList = _mapSessions->subscriptionListForClient(_authToken);
            if (subList.isEmpty()) {
                subList << sub;
            } else {
                // Replace any existing subscriptions with the same name with removeOne
                subList.removeOne(sub);
                subList << sub;
            }
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "subList size:" << subList.size();
            }

            _mapSessions->setSubscriptionListForClient(_authToken, subList);
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Adding SearchGraph to subscription lists with name:" << sub._name;
            }

            if (_mapSessions->haveActivePollForClient(_authToken)) {
                // signal to check subscriptions for polls
                sendResultsOnActivePolls();
            }

        } else if (subOper.subscribeType() == SubscribeOperation::Delete) {
            Subscription delSub(subReq.requestVersion());
            delSub._name = subOper.name();

            QList<Subscription> subList = _mapSessions->removeSubscriptionListForClient(_authToken);
            if (! subList.isEmpty()) {
                // remove delSub from list with same name
                subList.removeOne(delSub);
                if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                    qDebug() << __PRETTY_FUNCTION__ << ":" << "Removing subscription from subList with name:" << delSub._name;
                }
            } else {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "No subscriptions to delete for publisher:" << publisherId;
            }

            if (! subList.isEmpty()) {
                _mapSessions->setSubscriptionListForClient(_authToken, subList);
            }

            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "subList size:" << subList.size();
            }

        }
    }

    MapResponse subResp(subReq.requestVersion());
    if (requestError) {
        subResp.setErrorResponse(requestError, sessId);
    } else {
        subResp.setSubscribeResponse(sessId);
    }
    sendMapResponse(subResp);
}

void ClientHandler::processSearch(QVariant clientRequest)
{
    SearchRequest searchReq = clientRequest.value<SearchRequest>();
    MapResponse searchResp(searchReq.requestVersion());

    MapRequest::RequestError requestError = searchReq.requestError();
    QString sessId = searchReq.sessionId();

    if (!requestError) {
        Subscription tempSub(searchReq.requestVersion());
        tempSub._search = searchReq.search();

        int currentDepth = -1;
        buildSearchGraph(tempSub, tempSub._search.startId(), currentDepth);

        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Search Lists";
            // NB: idList size should be 1 or more, because we always include the starting identifier
            qDebug() << __PRETTY_FUNCTION__ << ":" << "    idList size:" << tempSub._idList.size();
            qDebug() << __PRETTY_FUNCTION__ << ":" << "    linkList size:" << tempSub._linkList.size();
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

    sendMapResponse(searchResp);
}

void ClientHandler::processPurgePublisher(QVariant clientRequest)
{
    PurgePublisherRequest ppReq = clientRequest.value<PurgePublisherRequest>();

    MapRequest::RequestError requestError = ppReq.requestError();
    QString sessId = ppReq.sessionId();
    QString publisherId = _mapSessions->pubIdForAuthToken(_authToken);

    if (!requestError) {
        QString purgePubId = ppReq.publisherId();
        /* IFMAP20: 3.7.6:
           A MAP Server MAY forbid a MAP Client to use the purgePublisher
           request to remove data published by a different MAP Client, in
           which case the MAP Server MUST respond with an AccessDenied error.
        */
        if (purgePubId.compare(publisherId) != 0) {
            // TODO: Set configuration option for this
            requestError = MapRequest::IfmapAccessDenied;
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Computed publisher-id and purgePublisher attribute do NOT match";
        }

        if (!requestError) {
            QHash<Id, QList<Meta> > idMetaDeleted;
            QHash<Link, QList<Meta> > linkMetaDeleted;
            bool haveChange = _mapGraph->deleteMetaWithPublisherId(purgePubId, &idMetaDeleted, &linkMetaDeleted);

            // Check subscriptions for changes to Map Graph
            if (haveChange) {
                updateSubscriptions(idMetaDeleted, linkMetaDeleted);
                sendResultsOnActivePolls();
                if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowMAPGraphAfterChange)) {
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
    sendMapResponse(ppResp);
}

void ClientHandler::processPoll(QVariant clientRequest)
{
    PollRequest pollReq = clientRequest.value<PollRequest>();

    MapRequest::RequestError requestError = pollReq.requestError();
    QString sessId = pollReq.sessionId();
    QString publisherId = _mapSessions->pubIdForAuthToken(_authToken);

    if (!requestError) {
        if (_mapSessions->ssrcForClient(_authToken) == this) {
            if (_omapdConfig->valueFor("allow_unauthenticated_clients").toBool()) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "NON-STANDARD: Allowing ARC on SSRC for pubId:" << publisherId;
            } else {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Error: Received poll request on SSRC for pubId:" << publisherId;
                // FIXME: Need to find out what is the expected error response here.
                //        Seems it could either be to send an endSessionResponse _or_
                //        to send an invalid session ID error.
                bool sendEndSessionResponse = false;
                if (sendEndSessionResponse) {
                    // Need to track the TCP socket this publisher's poll is on, for terminate to follow
                    _mapSessions->setActivePollForClient(_authToken, this);
                } else {
                    requestError = MapRequest::IfmapInvalidSessionID;
                }
                terminateSession(sessId, pollReq.requestVersion());
            }
        } else if (_mapSessions->haveActiveARCForClient(_authToken) &&
            (pollReq.requestVersion() == MapRequest::IFMAPv11)) {
            // Track the TCP socket this publisher's poll is on
            _mapSessions->setActivePollForClient(_authToken, this);

            if (_mapSessions->subscriptionListForClient(_authToken).isEmpty()) {
                // No immediate client response
                if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                    qDebug() << __PRETTY_FUNCTION__ << ":" << "No subscriptions for publisherId:" << publisherId;
                }
            } else {
                sendResultsOnActivePolls();
            }
        } else if (pollReq.requestVersion() == MapRequest::IFMAPv20) {
            // Terminate any existing ARC sessions
            if (_mapSessions->haveActivePollForClient(_authToken)) {
                // If we had an existing ARC session, end the session
                terminateSession(sessId, pollReq.requestVersion());
                requestError = MapRequest::IfmapInvalidSessionID;
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Already have existing ARC session, terminating";
            } else {
                if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                    qDebug() << __PRETTY_FUNCTION__ << ":" << "Adding ARC session for publisher:" << publisherId;
                }
                // We don't get an attach-session, so register ARC connection
                _mapSessions->setActiveARCForClient(_authToken, this);
                // Track the TCP socket this publisher's poll is on
                _mapSessions->setActivePollForClient(_authToken, this);

                if (_mapSessions->subscriptionListForClient(_authToken).isEmpty()) {
                    // No immediate client response
                    if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                        qDebug() << __PRETTY_FUNCTION__ << ":" << "No subscriptions for publisherId:" << publisherId;
                    }
                } else {
                    sendResultsOnActivePolls();
                }
            }
        } else {
            // Error
            requestError = MapRequest::IfmapInvalidSessionID;
            qDebug() << __PRETTY_FUNCTION__ << ":" << "No active ARC session for poll from publisherId:" << publisherId;
        }
    }

    /* IFMAP20: 3.7.5:
       If a server responds to a poll with an errorResult, all of the clients
       subscriptions are automatically invalidated and MUST be removed by the
       server.
    */
    if (requestError) {
        if (_mapSessions->removeSubscriptionListForClient(_authToken).size() > 0) {
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Removing subscriptions for publisherId:" << publisherId;
            }
        }

        MapResponse pollErrorResponse(pollReq.requestVersion());
        pollErrorResponse.setErrorResponse(requestError, sessId);
        sendMapResponse(pollErrorResponse);
    }
}

bool ClientHandler::terminateSession(QString sessionId, MapRequest::RequestVersion requestVersion)
{
    bool hadExistingSSRCSession = _mapSessions->haveActiveSSRCForClient(_authToken);
    if (hadExistingSSRCSession) {

        _mapSessions->removeActiveSSRCForClient(_authToken);

        QString publisherId = _mapSessions->pubIdForAuthToken(_authToken);

        /* IFMAP20: 3.7.4:
           When a MAP Client initially connects to a MAP Server, the MAP Server MUST
           delete any previous subscriptions corresponding to the MAP Client. In
           other words, subscription lists are only valid for a single MAP Client session.
        */
        if (_mapSessions->removeSubscriptionListForClient(_authToken).size() > 0) {
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Removing subscriptions for publisherId:"
                        << publisherId;
            }
        }

        /* IFMAP20: 4.3:
           When a session ends for any reason, and there is an outstanding poll
           request on the ARC, the MAP Server MUST send an endSessionResult to the
           MAP Client on the ARC.
        */
        terminateARCSession(sessionId, requestVersion);

        /* IFMAP20: 3.3.5:
           If an element was published with lifetime=session and the client
           session ends, either due to inactivity (see Section 4.1.1) or at the
           clients request, the MAP server MUST delete the metadata.   This
           deletion MUST be completed before the publishing client is allowed
           to create another session.
        */
        // Delete all session-level metadata for this publisher
        QHash<Id, QList<Meta> > idMetaDeleted;
        QHash<Link, QList<Meta> > linkMetaDeleted;
        bool haveChange = _mapGraph->deleteMetaWithPublisherId(publisherId, &idMetaDeleted, &linkMetaDeleted, true);
        // Check subscriptions for changes to Map Graph
        while (haveChange) {
            updateSubscriptions(idMetaDeleted, linkMetaDeleted);
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowMAPGraphAfterChange)) {
                _mapGraph->dumpMap();
            }
            idMetaDeleted.clear();
            linkMetaDeleted.clear();
            haveChange = _mapGraph->deleteMetaWithPublisherId(publisherId, &idMetaDeleted, &linkMetaDeleted, true);
        }
        sendResultsOnActivePolls();
    }

    return hadExistingSSRCSession;
}

bool ClientHandler::terminateARCSession(QString sessionId, MapRequest::RequestVersion requestVersion)
{
    bool hadExistingARCSession = _mapSessions->haveActiveARCForClient(_authToken);

    if (hadExistingARCSession) {
        QString publisherId = _mapSessions->pubIdForAuthToken(_authToken);

        // Terminate polls
        if (_mapSessions->haveActivePollForClient(_authToken)) {
            ClientHandler *client = _mapSessions->pollConnectionForClient(_authToken);
            if (requestVersion == MapRequest::IFMAPv20) {
                if (client && client->isValid()) {
                    if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps))
                        qDebug() << __PRETTY_FUNCTION__ << ":" << "Sending endSessionResult to publisherId:"
                                 << publisherId << "on client socket" << client;
                    MapResponse pollEndSessionResponse(MapRequest::IFMAPv20); // Has to be IF-MAP 2.0!
                    pollEndSessionResponse.setEndSessionResponse(sessionId);

                    emit needToSendPollResponse(client, pollEndSessionResponse.responseData(), pollEndSessionResponse.requestVersion());
                }
            }
            _mapSessions->removeActivePollForClient(_authToken);
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps))
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Terminated active poll for publisherId:" << publisherId;
        }

        // End active ARC Session
        _mapSessions->removeActiveARCForClient(_authToken);
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps))
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Ending active ARC Session for publisherId:"
                     << publisherId;
    }

    return hadExistingARCSession;
}

QString ClientHandler::filteredMetadata(Meta meta, QString filter, QMap<QString, QString> searchNamespaces, MapRequest::RequestError &error)
{
    QList<Meta> singleMetaList;
    singleMetaList.append(meta);
    return filteredMetadata(singleMetaList, filter, searchNamespaces, error);
}

QString ClientHandler::filteredMetadata(QList<Meta>metaList, QString filter, QMap<QString, QString>searchNamespaces, MapRequest::RequestError &error)
{
    QString resultString("");
    bool matchAll = false;

    /* The filter will be either a match-links, result-filter, or delete filter,
       depending on where this method is called.  The "invert" parameter reverses the
       sense of the filter, so if the filter is a delete filter, be sure
       to set invert = true.
    */
    /* Per IFMAP20: 3.7.2.3:match-links specifies the criteria for positive matching
       for including metadata from any link visited in the search. match-links also
       specifies the criteria for including linked identifiers in the search.
    */
    /* Per IFMAP20: 3.7.2.5: result-filter
       The filter specifies any further rules for deleting data from the results. If
       there is no result-filter attribute, all metadata on all identifiers and links
       that match the search is returned to the client. If an empty filter result-filter
       attribute is specified, the identifiers and links that match the search are
       returned to the client with no metadata.
    */

    if (filter.isEmpty()) {
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps))
            qDebug() << __PRETTY_FUNCTION__ << ":" << "Empty filter string matches nothing";
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

    if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLFilterStatements))
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Query Statement:" << endl << qString;

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
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Error running query!";
        error = MapRequest::IfmapSystemError;
    } else {
        // If there are no query results, we won't add <metadata> enclosing element
        if (! resultString.isEmpty()) {
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLFilterResults))
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Query Result:" << endl << resultString;

            resultString.prepend("<metadata>");
            resultString.append("</metadata>");
        }
    }

    return resultString;
}

void ClientHandler::addIdentifierResult(Subscription &sub, Identifier id, QList<Meta> metaList, SearchResult::ResultType resultType, MapRequest::RequestError &operationError)
{

    SearchResult *searchResult = new SearchResult(resultType, SearchResult::IdentifierResult);
    searchResult->_id = id;

    if (!metaList.isEmpty() && ! sub._search.resultFilter().isEmpty()) {
        QString metaString = filteredMetadata(metaList, sub._search.resultFilter(), sub._search.filterNamespaceDefinitions(), operationError);

        if (! metaString.isEmpty()) {
            searchResult->_metadata = metaString;
            sub._curSize += metaString.size();
            if (sub._curSize > sub._search.maxSize()) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Search results exceeded max-size with curSize:" << sub._curSize;
                operationError = MapRequest::IfmapSearchResultsTooBig;
                sub._subscriptionError = MapRequest::IfmapSearchResultsTooBig;
            }
        }
    }

    if (resultType == SearchResult::SearchResultType) {
        sub._searchResults.append(searchResult);
    } else {
        sub._deltaResults.append(searchResult);
    }
}

void ClientHandler::addLinkResult(Subscription &sub, Link link, QList<Meta> metaList, SearchResult::ResultType resultType, MapRequest::RequestError &operationError)
{

    SearchResult *searchResult = new SearchResult(resultType, SearchResult::LinkResult);
    searchResult->_link = link;

    if (!metaList.isEmpty() && ! sub._search.resultFilter().isEmpty()) {
        QString combinedFilter = sub._search.matchLinks();
        if (sub._search.resultFilter().compare("*") != 0) {
            combinedFilter = Subscription::intersectFilter(sub._search.matchLinks(), sub._search.resultFilter());
        }
        QString metaString = filteredMetadata(metaList, combinedFilter, sub._search.filterNamespaceDefinitions(), operationError);

        if (! metaString.isEmpty()) {
            searchResult->_metadata = metaString;
            sub._curSize += metaString.size();
            if (sub._curSize > sub._search.maxSize()) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Search results exceeded max-size with curSize:" << sub._curSize;
                operationError = MapRequest::IfmapSearchResultsTooBig;
                sub._subscriptionError = MapRequest::IfmapSearchResultsTooBig;
            }
        }
    }

    if (resultType == SearchResult::SearchResultType) {
        sub._searchResults.append(searchResult);
    } else {
        sub._deltaResults.append(searchResult);
    }
}

void ClientHandler::collectSearchGraphMetadata(Subscription &sub, SearchResult::ResultType resultType, MapRequest::RequestError &operationError)
{

    /* Per IFMAP20: 3.7.3: Since all identifiers for a given identifier type
       are always valid to search, the MAP Server MUST never return an
       identifier not found error when searching for an identifier. In this
       case, the MAP Server MUST return the identifier with no metadata or
       links attached to it.
    */
    QSetIterator<Id> idIt(sub._idList);
    while (idIt.hasNext() && !operationError) {
        Id id = idIt.next();
        QList<Meta> idMetaList = _mapGraph->metaForId(id);
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "idMetaList size for id:" << id << "-->" << idMetaList.size();
        }
        // TODO: Should the identifier be added if there is no metadata at all?
        addIdentifierResult(sub, id, idMetaList, resultType, operationError);
    }

    QSetIterator<Link> linkIt(sub._linkList);
    while (linkIt.hasNext() && !operationError) {
        Link link = linkIt.next();
        QList<Meta> linkMetaList = _mapGraph->metaForLink(link);
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "linkMetaList size for link:" << link << "-->" << linkMetaList.size();
        }
        addLinkResult(sub, link, linkMetaList, resultType, operationError);
    }
}

void ClientHandler::addUpdateAndDeleteMetadata(Subscription &sub, SearchResult::ResultType resultType, QSet<Id>idList, QSet<Link>linkList, MapRequest::RequestError &operationError)
{
    QSetIterator<Id> idIt(idList);
    while (idIt.hasNext() && !operationError) {
        Id id = idIt.next();
        QList<Meta> idMetaList = _mapGraph->metaForId(id);
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "idMetaList size for id:" << id << "-->" << idMetaList.size();
        }
        // Add the identifier only if there are metadata.
        if (idMetaList.size() > 0)
          addIdentifierResult(sub, id, idMetaList, resultType, operationError);
    }

    QSetIterator<Link> linkIt(linkList);
    while (linkIt.hasNext() && !operationError) {
        Link link = linkIt.next();
        QList<Meta> linkMetaList = _mapGraph->metaForLink(link);
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "linkMetaList size for link:" << link << "-->" << linkMetaList.size();
        }
        // Add the link only if there are metadata.
        if (linkMetaList.size() > 0)
          addLinkResult(sub, link, linkMetaList, resultType, operationError);
    }

    if (sub._curSize > MAXPOLLRESULTSIZEDEFAULT) { // TODO: Replace with client setting
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Search results exceeded max poll result size with curSize:" << sub._curSize;
        sub._subscriptionError = MapRequest::IfmapPollResultsTooBig;
    }
}

// currentDepth is pass by value!  Must initially be -1.
void ClientHandler::buildSearchGraph(Subscription &sub, Id startId, int currentDepth)
{
    /* IFMAP20: 3.7.2.8: Recursive Algorithm is from spec */
    // 1. Current id, current results, current depth
    currentDepth++;
    if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Starting identifier:" << startId;
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Current depth:" << currentDepth;
    }

    // 2. Save current identifier in list of traversed identifiers
    // so we can later gather metadata from these identifiers.
    sub._idList.insert(startId);

    // 3. If the current identifiers type is contained within
    // terminal-identifier-type, return current results.
    if (! sub._search.terminalId().isEmpty() && sub._requestVersion == MapRequest::IFMAPv20) {
        QString curIdTypeStr = Identifier::idBaseStringForType(startId.type());
        QStringList terminalIdList = sub._search.terminalId().split(",");

        if (terminalIdList.contains(curIdTypeStr)) {
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Reached terminal identifier:" << curIdTypeStr;
            }
            return;
        }
    }

    // 4. Check max depth reached
    if (currentDepth >= sub._search.maxDepth()) {
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "max depth reached:" << sub._search.maxDepth();
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
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "Adding link:" << link;
            }
            linksWithCurId.insert(link);
        }
    }

    // Remove links we've already seen before
    linksWithCurId.subtract(sub._linkList);

    if (linksWithCurId.isEmpty()) {
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "linksWithCurId is empty!!!";
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

void ClientHandler::updateSubscriptions(QHash<Id, QList<Meta> > idMetaDeleted, QHash<Link, QList<Meta> > linkMetaDeleted)
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
void ClientHandler::updateSubscriptions(Link link, bool isLink, QList<Meta> metaChanges, Meta::PublishOperationType publishType)
{
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

    QHashIterator<QString,QList<Subscription> > allSubsIt(_mapSessions->subscriptionLists());
    while (allSubsIt.hasNext()) {
        allSubsIt.next();
        QString authToken = allSubsIt.key();
        QString pubId = _mapSessions->pubIdForAuthToken(authToken);
        QList<Subscription> subList = allSubsIt.value();
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "publisher:" << pubId << "has num subscriptions:" << subList.size();
        }

        bool publisherHasDirtySub = false;
        QMutableListIterator<Subscription> subIt(subList);
        while (subIt.hasNext()) {
            Subscription sub = subIt.next();
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "--checking subscription named:" << sub._name;
            }

            QSet<Id> idsWithConnectedGraphUpdates, idsWithConnectedGraphDeletes;
            QSet<Link> linksWithConnectedGraphUpdates, linksWithConnectedGraphDeletes;
            bool modifiedSearchGraph = false;
            bool subIsDirty = false;

            if (! isLink) {
                if (sub._idList.contains(link.first)) {
                    // Case 1.
                    subIsDirty = true;
                    if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                        qDebug() << __PRETTY_FUNCTION__ << ":" << "----subscription is dirty with id in SearchGraph:" << link.first;
                    }
                }
            } else {
                if (sub._linkList.contains(link) && publishType == Meta::PublishDelete) {
                    // Case 3.
                    subIsDirty = true;
                    if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                        qDebug() << __PRETTY_FUNCTION__ << ":" << "----subscription is dirty with link in SearchGraph:" << link;
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

                        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                            qDebug() << __PRETTY_FUNCTION__ << ":" << "----subscription is dirty with newIdList.size:" << sub._idList.size();
                        }
                    }

                    if (sub._linkList != existingLinkList) {
                        subIsDirty = true;
                        modifiedSearchGraph = true;
                        // Metadata on these links are in updateResults
                        linksWithConnectedGraphUpdates = sub._linkList - existingLinkList;
                        // Metadata on these links are in deleteResults
                        linksWithConnectedGraphDeletes = existingLinkList - sub._linkList;

                        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                            qDebug() << __PRETTY_FUNCTION__ << ":" << "----subscription is dirty with newLinkList.size:" << sub._linkList.size();
                        }
                    }
                }
            }

            if (subIsDirty && !sub._subscriptionError) {
                // Construct results for the subscription
                if (sub._requestVersion == MapRequest::IFMAPv11) {
                    // Trigger to build and send pollResults
                    sub._sentFirstResult = false;
                } else if (sub._sentFirstResult && sub._requestVersion == MapRequest::IFMAPv20) {
                    MapRequest::RequestError error = MapRequest::ErrorNone;
                    // Add results from publish/delete/endSession/purgePublisher (that don't modify SearchGraph)
                    if (!modifiedSearchGraph || publishType == Meta::PublishDelete) {
                        SearchResult::ResultType resultType = SearchResult::resultTypeForPublishType(publishType);
                        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                            qDebug() << __PRETTY_FUNCTION__ << ":" << "----adding update/delete results from un-changed SearchGraph";
                        }
                        if (isLink) {
                            addLinkResult(sub, link, metaChanges, resultType, error);
                        } else {
                            addIdentifierResult(sub, link.first, metaChanges, resultType, error);
                        }
                    }
                    // Add results from extending SearchGraph for this subscription
                    if (!idsWithConnectedGraphUpdates.isEmpty() || !linksWithConnectedGraphUpdates.isEmpty()) {
                        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                            qDebug() << __PRETTY_FUNCTION__ << ":" << "----adding updateResults from changed SearchGraph";
                        }
                        addUpdateAndDeleteMetadata(sub, SearchResult::UpdateResultType, idsWithConnectedGraphUpdates, linksWithConnectedGraphUpdates, error);
                    }
                    // Add results from pruning SearchGraph for this subscription
                    if (!idsWithConnectedGraphDeletes.isEmpty() || !linksWithConnectedGraphDeletes.isEmpty()) {
                        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                            qDebug() << __PRETTY_FUNCTION__ << ":" << "----adding deleteResults from changed SearchGraph";
                        }
                        addUpdateAndDeleteMetadata(sub, SearchResult::DeleteResultType, idsWithConnectedGraphDeletes, linksWithConnectedGraphDeletes, error);
                    }
                }
                subIt.setValue(sub);
                publisherHasDirtySub = true;
            }
        }

        if (publisherHasDirtySub) {
            _mapSessions->setSubscriptionListForClient(authToken, subList);
        }
    }
}

// Iterate over all subscriptions for all publishers, checking the SearchGraphs
// to see if subscriptions match the notify metadata.  If a subscription matches,
// mark the subscription as dirty, so that we can send out pollResults.
void ClientHandler::updateSubscriptionsWithNotify(Link link, bool isLink, QList<Meta> notifyMetaList)
{
    // An existing subscription becomes dirty in 3 cases:
    // 1. metadata is publish-notify on an identifier in the SearchGraph
    // 2. metadata is publish-notify on a link in the SearchGraph
    // 3. metadata is publish-notify on a link with one identifier in the SearchGraph

    QHashIterator<QString,QList<Subscription> > allSubsIt(_mapSessions->subscriptionLists());
    while (allSubsIt.hasNext()) {
        allSubsIt.next();
        QString authToken = allSubsIt.key();
        QString pubId = _mapSessions->pubIdForAuthToken(authToken);
        QList<Subscription> subList = allSubsIt.value();
        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
            qDebug() << __PRETTY_FUNCTION__ << ":" << "publisher:" << pubId << "has num subscriptions:" << subList.size();
        }

        bool publisherHasDirtySub = false;
        QMutableListIterator<Subscription> subIt(subList);
        while (subIt.hasNext()) {
            Subscription sub = subIt.next();
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "--checking subscription named:" << sub._name;
            }
            bool subIsDirty = false;

            if (! isLink) {
                // Case 1.
                if (sub._idList.contains(link.first)) {
                    subIsDirty = true;
                    if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                        qDebug() << __PRETTY_FUNCTION__ << ":" << "----subscription is dirty with id in SearchGraph:" << link.first;
                    }
                }
            } else {
                if (sub._linkList.contains(link)) {
                    // Case 2.
                    subIsDirty = true;
                    if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                        qDebug() << __PRETTY_FUNCTION__ << ":" << "----subscription is dirty with link in SearchGraph:" << link;
                    }
                } else if (sub._idList.contains(link.first) || sub._idList.contains(link.second)) {
                    // Case 3.
                    subIsDirty = true;
                    if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                        qDebug() << __PRETTY_FUNCTION__ << ":" << "----subscription is dirty with one end of the link in SearchGraph:" << link;
                    }
                }
            }

            if (subIsDirty && !sub._subscriptionError) {
                // Construct results for the subscription
                MapRequest::RequestError error = MapRequest::ErrorNone;
                if (isLink) {
                    addLinkResult(sub, link, notifyMetaList, SearchResult::NotifyResultType, error);
                } else {
                    addIdentifierResult(sub, link.first, notifyMetaList, SearchResult::NotifyResultType, error);
                }

                if (sub._curSize > MAXPOLLRESULTSIZEDEFAULT) { // TODO: Replace with client setting
                    qDebug() << __PRETTY_FUNCTION__ << ":" << "Search results exceeded max poll result size with curSize:" << sub._curSize;
                    sub._subscriptionError = MapRequest::IfmapPollResultsTooBig;
                }

                subIt.setValue(sub);
                publisherHasDirtySub = true;
            }
        }

        if (publisherHasDirtySub) {
            _mapSessions->setSubscriptionListForClient(authToken, subList);
        }
    }
}

void ClientHandler::sendResultsOnActivePolls()
{
    // TODO: Often this slot gets signaled from a method that really only needs to
    // send results on active polls for a specific publisherId.  Could optimize
    // this slot in those cases.
    QHashIterator<QString,QList<Subscription> > allSubsIt(_mapSessions->subscriptionLists());
    while (allSubsIt.hasNext()) {
        allSubsIt.next();
        QString authToken = allSubsIt.key();
        // Only check subscriptions for publisher if client has an active poll
        if (_mapSessions->haveActivePollForClient(authToken)) {
            QString pubId = _mapSessions->pubIdForAuthToken(authToken);
            QList<Subscription> subList = allSubsIt.value();
            if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                qDebug() << __PRETTY_FUNCTION__ << ":" << "publisher:" << pubId << "has num subscriptions:" << subList.size();
            }

            bool publisherHasError = false;
            MapResponse *pollResponse = 0;
            MapRequest::RequestVersion pollResponseVersion = MapRequest::VersionNone;

            QMutableListIterator<Subscription> subIt(subList);
            while (subIt.hasNext()) {
                Subscription sub = subIt.next();

                MapRequest::RequestError subError = MapRequest::ErrorNone;
                if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                    qDebug() << __PRETTY_FUNCTION__ << ":" << "--Checking subscription named:" << sub._name;
                }

                if (pollResponseVersion == MapRequest::VersionNone) {
                    pollResponseVersion = sub._requestVersion;
                }

                if (sub._subscriptionError) {
                    if (!pollResponse) {
                        pollResponse = new MapResponse(pollResponseVersion);
                        pollResponse->startPollResponse(_mapSessions->sessIdForClient(authToken));
                    }
                    pollResponse->addPollErrorResult(sub._name, sub._subscriptionError);

                    sub.clearSearchResults();
                    subIt.setValue(sub);

                    publisherHasError = true;
                } else if (!sub._sentFirstResult) {
                    // Build results from entire search graph for the first poll response
                    collectSearchGraphMetadata(sub, SearchResult::SearchResultType, subError);

                    if (subError) {
                        qDebug() << __PRETTY_FUNCTION__ << ":" << "Search results exceeded max-size with curSize:" << sub._curSize;
                        sub._subscriptionError = subError;
                        sub.clearSearchResults();
                        publisherHasError = true;

                        if (!pollResponse) {
                            pollResponse = new MapResponse(pollResponseVersion);
                            pollResponse->startPollResponse(_mapSessions->sessIdForClient(authToken));
                        }
                        pollResponse->addPollErrorResult(sub._name, sub._subscriptionError);
                        subIt.setValue(sub);
                    } else if (sub._searchResults.count() > 0) {
                        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                            qDebug() << __PRETTY_FUNCTION__ << ":" << "--Gathering initial poll results for publisher with active poll:" << pubId;
                        }

                        if (!pollResponse) {
                            pollResponse = new MapResponse(pollResponseVersion);
                            pollResponse->startPollResponse(_mapSessions->sessIdForClient(authToken));
                        }
                        pollResponse->addPollResults(sub._searchResults, sub._name);
                        sub.clearSearchResults();

                        sub._sentFirstResult = true;
                        subIt.setValue(sub);
                    } else if (sub._curSize > MAXPOLLRESULTSIZEDEFAULT &&
                               sub._requestVersion == MapRequest::IFMAPv20) { // TODO: Replace with client setting
                        qDebug() << __PRETTY_FUNCTION__ << ":" << "Search results exceeded max poll result size with curSize:" << sub._curSize;
                        sub._subscriptionError = MapRequest::IfmapPollResultsTooBig;
                        sub.clearSearchResults();
                        publisherHasError = true;

                        if (!pollResponse) {
                            pollResponse = new MapResponse(pollResponseVersion);
                            pollResponse->startPollResponse(_mapSessions->sessIdForClient(authToken));
                        }
                        pollResponse->addPollErrorResult(sub._name, sub._subscriptionError);
                        subIt.setValue(sub);
                    } else {
                        if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                            qDebug() << __PRETTY_FUNCTION__ << ":" << "--No results for subscription at this time";
                            qDebug() << __PRETTY_FUNCTION__ << ":" << "----haveActivePollForClient(authToken):" << _mapSessions->haveActivePollForClient(authToken);
                        }
                    }
                } else if (sub._deltaResults.count() > 0) {
                    // Build results from update/delete/notify results
                    if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps)) {
                        qDebug() << __PRETTY_FUNCTION__ << ":" << "--Gathering delta poll results for publisher with active poll:" << pubId;
                    }

                    if (!pollResponse) {
                        pollResponse = new MapResponse(pollResponseVersion);
                        pollResponse->startPollResponse(_mapSessions->sessIdForClient(authToken));
                    }
                    pollResponse->addPollResults(sub._deltaResults, sub._name);

                    sub.clearSearchResults();
                    subIt.setValue(sub);
                }
            }

            if (pollResponse) {
                if (_omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps))
                    qDebug() << __PRETTY_FUNCTION__ << ":" << "Sending pollResults";
                pollResponse->endPollResponse();
                emit needToSendPollResponse(_mapSessions->pollConnectionForClient(authToken), pollResponse->responseData(), pollResponse->requestVersion());
                delete pollResponse;
                // Update subscription list for this publisher
                _mapSessions->setSubscriptionListForClient(authToken, subList);
                _mapSessions->removeActivePollForClient(authToken);
            }

            if (publisherHasError) {
                /* IFMAP20: 3.7.5:
                If a server responds to a poll with an errorResult, all of the clients
                subscriptions are automatically invalidated and MUST be removed by the
                server.
                */
                if (pollResponseVersion == MapRequest::IFMAPv20) {
                    qDebug() << __PRETTY_FUNCTION__ << ":" << "Removing subscriptions for publisherId:" << pubId;
                    _mapSessions->removeSubscriptionListForClient(authToken);
                }

                _mapSessions->removeActivePollForClient(authToken);
            }
        }
    }
}
