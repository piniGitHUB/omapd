/*
clientparser.h: Declaration of ClientParser class

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

#ifndef CLIENTPARSER_H
#define CLIENTPARSER_H

#include <QObject>
#include <QTcpSocket>
#include <QXmlStreamReader>
#include <QMap>

#include "maprequest.h"
#include "identifier.h"
#include "omapdconfig.h"

class ClientParser : public QObject
{
    Q_OBJECT
public:
    ClientParser(QObject *parent = 0);
    ~ClientParser();

    bool read(QTcpSocket *clientSocket);
    QString errorString() const { return _xmlReader.errorString(); }
    QXmlStreamReader::Error error() const { return _xmlReader.error(); }

    QVariant request() const { return _mapRequest; }
    MapRequest::RequestError requestError() const { return _requestError; }
    MapRequest::RequestVersion requestVersion() const { return _requestVersion; }
    MapRequest::RequestType requestType() const { return _requestType; }
    QString sessionId() const { return _sessionId; }

private:
    void readSoapEnvelope();
    void readSoapHeader();
    void readSoapBody();
    void readMapRequest();

    void setSessionId(MapRequest &request);

    void readNewSession();
    void readAttachSession();
#ifdef IFMAP20
    void readRenewSession();
    void readEndSession();
#endif //IFMAP20
    void readPurgePublisher();
    void readPublish();
    void readSubscribe();
    void readSearch();
    void readPoll();

    void readPublishOperation(PublishRequest &pubReq);
    void readSubscribeOperation(SubscribeRequest &subReq);
    SearchType parseSearch(MapRequest &request);

    Link readLink(MapRequest &request, bool &isLink);
    Id readIdentifier(MapRequest &request);
    QList<Meta> readMetadata(PublishRequest &pubReq, Meta::Lifetime lifetime = Meta::LifetimeForever);

    void registerMetadataNamespaces();

private:
    OmapdConfig* _omapdConfig;

    QXmlStreamReader _xmlReader;
    // mapping of prefix --> namespace for metadata types
    QMap<QString,QString> _namespaces;

    MapRequest::RequestError _requestError;
    MapRequest::RequestVersion _requestVersion;
    MapRequest::RequestType _requestType;

    QString _sessionId;
    bool _clientSetSessionId;

    QVariant _mapRequest;
};

#endif // CLIENTPARSER_H
