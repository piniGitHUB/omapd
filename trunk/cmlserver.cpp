/*
cmlserver.cpp: Implementation of CmlServer class

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

#include "cmlserver.h"

CmlServer::CmlServer(quint16 port, QObject *parent)
        : QTcpServer(parent)
{
    const char *fnName = "CmlServer::Server:";

    _debug = CmlServer::DebugNone;
    _serverCapability = CmlServer::DisableClientCertVerify;

    bool listening = listen(QHostAddress::LocalHost, port);
    if (!listening) {
        qDebug() << fnName << "Server will not listen on port:" << port;
    } else {
        this->setMaxPendingConnections(30); // 30 is QTcpServer default

        if (! _serverCapability.testFlag(CmlServer::DisableHTTPS)) {
            // Set server cert, private key, CRLs, etc.
        }

        connect(this, SIGNAL(headerReceived(QTcpSocket*,QNetworkRequest)),
                this, SLOT(processHeader(QTcpSocket*,QNetworkRequest)));
        connect(this, SIGNAL(getReqReceived(QTcpSocket*,QString)),
                this, SLOT(processGetReq(QTcpSocket*,QString)));
        connect(this, SIGNAL(putReqReceived(QTcpSocket*,QString)),
                this, SLOT(processPutReq(QTcpSocket*,QString)));
        connect(this, SIGNAL(postReqReceived(QTcpSocket*,QString)),
                this, SLOT(processPostReq(QTcpSocket*,QString)));
        connect(this, SIGNAL(delReqReceived(QTcpSocket*,QString)),
                this, SLOT(processDelReq(QTcpSocket*,QString)));
    }
}

void CmlServer::incomingConnection(int socketDescriptor)
{
    const char *fnName = "CmlServer::incomingConnection:";
    if (_serverCapability.testFlag(CmlServer::DisableHTTPS)) {
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
    } else {
        QSslSocket *sslSocket = new QSslSocket(this);
        if (sslSocket->setSocketDescriptor(socketDescriptor)) {

            sslSocket->setCiphers(QSslSocket::supportedCiphers());
            // TODO: Figure out how to just support QSsl::SslV3 & QSsl::TlsV1
            // QSsl::AnyProtocol accepts QSsl::SslV2 which is insecure
            sslSocket->setProtocol(QSsl::AnyProtocol);

            // TODO: Have an option to set QSslSocket::setPeerVerifyDepth
            if (_serverCapability.testFlag(CmlServer::DisableClientCertVerify)) {
                // QueryPeer just asks for the client cert, but does not verify it
                sslSocket->setPeerVerifyMode(QSslSocket::QueryPeer);
            } else {
                sslSocket->setPeerVerifyMode(QSslSocket::VerifyPeer);
            }

            // Connect SSL error signals to local slots
            connect(sslSocket, SIGNAL(peerVerifyError(QSslError)),
                    this, SLOT(clientSSLVerifyError(QSslError)));
            connect(sslSocket, SIGNAL(sslErrors(QList<QSslError>)),
                    this, SLOT(clientSSLErrors(QList<QSslError>)));

            // Setup server private keys
            // TODO: Make these configurable
            sslSocket->setPrivateKey("server.key");
            QFile certFile("server.pem");
            QList<QSslCertificate> serverCerts = QSslCertificate::fromPath("server.pem");
            QSslCertificate serverCert = serverCerts.at(0);
            if (serverCert.isValid()) {
                qDebug() << fnName << "Successfully set server certificate:"
                        << serverCert.subjectInfo(QSslCertificate::CommonName)
                        << "for peer:" << sslSocket->peerAddress().toString();
                sslSocket->setLocalCertificate(serverCert);

                connect(sslSocket, SIGNAL(encrypted()), this, SLOT(socketReady()));
                sslSocket->startServerEncryption();

            } else {
                qDebug() << fnName << "Error setting server certificate";
            }
        } else {
            qDebug() << fnName << "Error setting SSL socket descriptor on QSslSocket";
            delete sslSocket;
        }
    }
}

void CmlServer::clientSSLVerifyError(const QSslError &error)
{
    const char *fnName = "CmlServer::clientSSLVerifyError:";
    //QSslSocket *sslSocket = (QSslSocket *)sender();

    qDebug() << fnName << error.errorString();
}

void CmlServer::clientSSLErrors(const QList<QSslError> &errors)
{
    const char *fnName = "CmlServer::clientSSLErrors:";
    QSslSocket *sslSocket = (QSslSocket *)sender();

    foreach (const QSslError &error, errors) {
        qDebug() << fnName << error.errorString();
    }

    qDebug() << fnName << "Calling ignoreSslErrors";
    sslSocket->ignoreSslErrors();
}

void CmlServer::socketReady()
{
    const char *fnName = "CmlServer::socketReady:";
    QSslSocket *sslSocket = (QSslSocket *)sender();
    qDebug() << fnName << "Successful SSL handshake with peer:" << sslSocket->peerAddress().toString();

    bool clientAuthorized = false;

    if (_serverCapability.testFlag(CmlServer::DisableClientCertVerify)) {
        qDebug() << fnName << "Client authorized because CmlServer::DisableClientCertVerify is set, for peer:"
                 << sslSocket->peerAddress().toString();
        clientAuthorized = true;
    } else {
        clientAuthorized = authorizeClient(sslSocket);
    }

    if (clientAuthorized) {
        connect(sslSocket, SIGNAL(readyRead()), this, SLOT(readClient()));
        connect(sslSocket, SIGNAL(disconnected()), this, SLOT(discardClient()));
        connect(sslSocket, SIGNAL(stateChanged(QAbstractSocket::SocketState)),
                this, SLOT(clientConnState(QAbstractSocket::SocketState)));
    } else {
        if (_debug.testFlag(CmlServer::ShowClientOps))
            qDebug() << fnName << "Disconnecting unauthorized client at:" << sslSocket->peerAddress().toString();
        sslSocket->disconnectFromHost();
        sslSocket->deleteLater();
    }
}

bool CmlServer::authorizeClient(QSslSocket *sslSocket)
{
    const char *fnName = "CmlServer::authorizeClient:";

    QList<QSslCertificate> clientCerts = sslSocket->peerCertificateChain();
    qDebug() << fnName << "Cert chain for client at:" << sslSocket->peerAddress().toString();
    for (int i=0; i<clientCerts.size(); i++) {
        qDebug() << fnName << "-- CN:" << clientCerts.at(i).subjectInfo(QSslCertificate::CommonName);
    }

    // TODO: add authorization and policy layer
    return true;
}

void CmlServer::newClientConnection()
{
    while (this->hasPendingConnections()) {
        QTcpSocket *socket = this->nextPendingConnection();
        connect(socket, SIGNAL(readyRead()), this, SLOT(readClient()));
        connect(socket, SIGNAL(disconnected()), this, SLOT(discardClient()));
        connect(socket, SIGNAL(stateChanged(QAbstractSocket::SocketState)),
                this, SLOT(clientConnState(QAbstractSocket::SocketState)));
    }
}

void CmlServer::clientConnState(QAbstractSocket::SocketState sState)
{
    const char *fnName = "CmlServer::clientConnState:";

    QTcpSocket* socket = (QTcpSocket*)sender();

    if (_debug.testFlag(CmlServer::ShowHTTPState))
        qDebug() << fnName << "socket state for socket:" << socket
                 << "------------->:" << sState;

}

void CmlServer::readClient()
{
    const char *fnName = "CmlServer::readClient:";
    QTcpSocket* socket = (QTcpSocket*)sender();

    bool readError = false;
    qint64 nBytesAvailable = socket->bytesAvailable();
    QByteArray requestByteArr;

    while (nBytesAvailable && !readError) {
        // No header received yet
        if (readHeader(socket)) {
        } else {
            // Error - invalid header
            readError = true;
        }

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

        nBytesAvailable = socket->bytesAvailable();
    }

    if (_debug.testFlag(CmlServer::ShowRawSocketData))
        qDebug() << fnName << "Raw Socket Data:" << endl << requestByteArr;
}

int CmlServer::readHeader(QTcpSocket *socket)
{
    const char *fnName = "CmlServer::readHeader:";
    QNetworkRequest requestWithHdr;
    bool end = false;
    QString tmp;
    QString headerStr = QLatin1String("");
    QString getReq, putReq, postReq, delReq;

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
            } else {
                if (tmp.contains("GET", Qt::CaseInsensitive)) {
                    int lIndex = tmp.indexOf("GET ");
                    int rIndex = tmp.indexOf(" HTTP");
                    getReq = tmp.mid(lIndex, rIndex - lIndex);
                    qDebug() << fnName << "Recieved GET request:" << getReq;
                } else if (tmp.contains("PUT", Qt::CaseInsensitive)) {
                    int lIndex = tmp.indexOf("PUT ");
                    int rIndex = tmp.indexOf(" HTTP");
                    putReq = tmp.mid(lIndex, rIndex - lIndex);
                    qDebug() << fnName << "Recieved PUT request:" << putReq;
                } else if (tmp.contains("POST", Qt::CaseInsensitive)) {
                    int lIndex = tmp.indexOf("POST ");
                    int rIndex = tmp.indexOf(" HTTP");
                    postReq = tmp.mid(lIndex, rIndex - lIndex);
                    qDebug() << fnName << "Recieved POST request:" << postReq;
                } else if (tmp.contains("DELETE", Qt::CaseInsensitive)) {
                    int lIndex = tmp.indexOf("DELETE ");
                    int rIndex = tmp.indexOf(" HTTP");
                    delReq = tmp.mid(lIndex, rIndex - lIndex);
                    qDebug() << fnName << "Recieved DELETE request:" << delReq;
                }
            }
            headerStr += tmp;
        }
    }

    if (end) {
        emit headerReceived(socket, requestWithHdr);
        if (! getReq.isEmpty()) emit getReqReceived(socket, getReq);
        if (! putReq.isEmpty()) emit putReqReceived(socket, putReq);
        if (! postReq.isEmpty()) emit postReqReceived(socket, postReq);
        if (! delReq.isEmpty()) emit delReqReceived(socket, delReq);
    }

    if (_debug.testFlag(CmlServer::ShowHTTPHeaders))
        qDebug() << fnName << "headerStr:" << endl << headerStr;

    return headerStr.length();
}

void CmlServer::processHeader(QTcpSocket *socket, QNetworkRequest requestHdrs)
{
    const char *fnName = "CmlServer::processHeader:";

    // TODO: Improve http protocol support

    // Get CML Commands
    if (requestHdrs.hasRawHeader(QByteArray("Expect"))) {
        if (_debug.testFlag(CmlServer::ShowHTTPHeaders))
            qDebug() << fnName << "Got Expect header";
        QByteArray expectValue = requestHdrs.rawHeader(QByteArray("Expect"));
        if (! expectValue.isEmpty() && expectValue.contains(QByteArray("100-continue"))) {
            if (_debug.testFlag(CmlServer::ShowHTTPHeaders)) {
                qDebug() << fnName << "Got 100-continue Expect Header";
            }
            sendHttpResponse(socket, 100, "Continue");
        }
    }

    if (requestHdrs.hasRawHeader(QByteArray("Authorization"))) {
        if (_debug.testFlag(CmlServer::ShowHTTPHeaders))
            qDebug() << fnName << "Got Authorization header";
        QByteArray basicAuthValue = requestHdrs.rawHeader(QByteArray("Authorization"));
        if (! basicAuthValue.isEmpty() && basicAuthValue.contains(QByteArray("Basic"))) {
            basicAuthValue = basicAuthValue.mid(6);
            if (_debug.testFlag(CmlServer::ShowHTTPHeaders)) {
                qDebug() << fnName << "Got Basic Auth value:" << basicAuthValue;
            }
        }
    }
}

void CmlServer::sendHttpResponse(QTcpSocket *socket, int hdrNumber, QString hdrText)
{
    const char *fnName = "CmlServer::sendHttpResponse:";

    if (_debug.testFlag(CmlServer::ShowHTTPHeaders)) {
        qDebug() << fnName << "Sending Http Response:" << hdrNumber << hdrText;
    }

    QHttpResponseHeader header(hdrNumber, hdrText);
    if (socket->state() == QAbstractSocket::ConnectedState) {
        socket->write(header.toString().toUtf8() );
    }
}

void CmlServer::sendResponse(QTcpSocket *socket, const QByteArray &respArr)
{
    const char *fnName = "CmlServer::sendResponse:";

    QHttpResponseHeader header(200,"OK");
    header.setContentType("text/xml");
    //header.setValue("Content-Encoding","UTF-8");
    header.setContentLength( respArr.size() );
    header.setValue("Server","omapd/cml");

    if (socket->state() == QAbstractSocket::ConnectedState) {
        socket->write(header.toString().toUtf8() );
        socket->write( respArr );

        if (_debug.testFlag(CmlServer::ShowHTTPHeaders))
            qDebug() << fnName << "Sent reply headers to client:" << endl << header.toString();

        if (_debug.testFlag(CmlServer::ShowRawSocketData))
            qDebug() << fnName << "Sent reply to client:" << endl << respArr << endl;
    } else {
        qDebug() << fnName << "Socket is not connected!  Not sending reply to client";
    }
}

void CmlServer::discardClient()
{
    QTcpSocket *socket = (QTcpSocket *)sender();
    socket->deleteLater();
}

void CmlServer::processGetReq(QTcpSocket *socket, QString getReq)
{
    const char *fnName = "CmlServer::processGetReq:";

    if (getReq.compare("GET /config") == 0) {

    } else if (getReq.compare("GET /config/server") == 0) {

    } else if (getReq.compare("GET /config/server/port") == 0) {
        quint16 port = _server->serverPort();
        QString pStr;
        pStr.setNum(port);
        qDebug() << fnName << "Got server port:" << pStr;
        sendResponse(socket, QByteArray(pStr.toUtf8()));
    }
}

void CmlServer::processPutReq(QTcpSocket *socket, QString putReq)
{
    const char *fnName = "CmlServer::processPutReq:";
    qDebug() << fnName << "Got PUT cmd:" << putReq << "on socket:" << socket;
}

void CmlServer::processPostReq(QTcpSocket *socket, QString postReq)
{
    const char *fnName = "CmlServer::processPostReq:";
    qDebug() << fnName << "Got POST cmd:" << postReq << "on socket:" << socket;
}

void CmlServer::processDelReq(QTcpSocket *socket, QString delReq)
{
    const char *fnName = "CmlServer::processDelReq:";
    qDebug() << fnName << "Got DELETE cmd:" << delReq << "on socket:" << socket;
}
