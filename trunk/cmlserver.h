/*
cmlserver.h: Definition of CmlServer class

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

#ifndef CMLSERVER_H
#define CMLSERVER_H

#include <QTcpServer>
#include <QSslSocket>
#include <QNetworkRequest>

#include "server.h"

class CmlServer : public QTcpServer
{
    Q_OBJECT
public:
    enum Debug {
                DebugNone = 0x0001,
                ShowClientOps = 0x0002,
                ShowHTTPHeaders = 0x0008,
                ShowHTTPState = 0x0010,
                ShowRawSocketData = 0x0200
               };
    Q_DECLARE_FLAGS(DebugOptions, Debug);

    enum ServerCapability {
        DisableHTTPS = 0x01,
        DisableClientCertVerify = 0x02
    };
    Q_DECLARE_FLAGS(ServerCapabilityOptions, ServerCapability);

    CmlServer(quint16 port = 8080, QObject *parent = 0);

    void setServer(Server *server) { _server = server; }

public slots:
    // config setters
    void setDebug(CmlServer::DebugOptions debug) { _debug = debug; }
    void setServerCapability(CmlServer::ServerCapabilityOptions options) { _serverCapability = options; }

    // config getters
    CmlServer::DebugOptions getDebug() const {return _debug; }
    CmlServer::ServerCapabilityOptions getServerCapability() const { return _serverCapability; }

signals:
    void headerReceived(QTcpSocket *socket, QNetworkRequest requestHdrs);
    void getReqReceived(QTcpSocket *socket, QString getReq);
    void putReqReceived(QTcpSocket *socket, QString putReq);
    void postReqReceived(QTcpSocket *socket, QString postReq);
    void delReqReceived(QTcpSocket *socket, QString delReq);

private:
    void incomingConnection(int socketDescriptor);
    int readHeader(QTcpSocket *socket);
    int readRequestData(QTcpSocket *socket);
    void sendHttpResponse(QTcpSocket *socket, int hdrNumber, QString hdrText);
    void sendResponse(QTcpSocket *socket, const QByteArray &respArr);
    bool authorizeClient(QSslSocket *sslSocket);

private slots:
    void socketReady();
    void clientSSLVerifyError(const QSslError & error);
    void clientSSLErrors(const QList<QSslError> & errors);
    void newClientConnection();
    void readClient();
    void processHeader(QTcpSocket *socket, QNetworkRequest requestHdrs);
    void discardClient();
    void clientConnState(QAbstractSocket::SocketState sState);
    void processGetReq(QTcpSocket *socket, QString getReq);
    void processPutReq(QTcpSocket *socket, QString putReq);
    void processPostReq(QTcpSocket *socket, QString postReq);
    void processDelReq(QTcpSocket *socket, QString delReq);

private:
    CmlServer::DebugOptions _debug;
    CmlServer::ServerCapabilityOptions _serverCapability;

    Server *_server;
};
Q_DECLARE_OPERATORS_FOR_FLAGS(CmlServer::DebugOptions)
Q_DECLARE_OPERATORS_FOR_FLAGS(CmlServer::ServerCapabilityOptions)

#endif // CMLSERVER_H
