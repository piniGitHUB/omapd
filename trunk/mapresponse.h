/*
mapresponse.h: Declaration of MapResponse class

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

#ifndef MAPRESPONSE_H
#define MAPRESPONSE_H

#include "maprequest.h"
#include "subscription.h"

#define SOAPv11_ENVELOPE    "http://schemas.xmlsoap.org/soap/envelope/"
#define SOAPv11_ENCODING    "http://schemas.xmlsoap.org/soap/encoding/"

#define SOAPv12_ENVELOPE    "http://www.w3.org/2003/05/soap-envelope"
#define SOAPv12_ENCODING    "http://www.w3.org/2003/05/soap-encoding"

#define XML_SCHEMA          "http://www.w3.org/1999/XMLSchema"
#define XML_SCHEMA_INSTANCE "http://www.w3.org/1999/XMLSchema-instance"
#define XML_NAMESPACE       "http://www.w3.org/XML/1998/namespace"

class MapResponse
{
public:
    enum ResponseType {
        ResponseNone = 0,
        ClientSoapFault,
        ErrorResult,
        NewSession,
        AttachSession,
        EndSession,
        RenewSession,
        Publish,
        Subscribe,
        Search,
        PurgePublisher,
        Poll
    };

    MapResponse(MapRequest::RequestVersion reqVersion);
    ~MapResponse();

    QByteArray responseData() const { return _responseBuffer.data(); }
    MapRequest::RequestVersion requestVersion() const { return _requestVersion; }

    void setClientFault(QString faultString);

    void setErrorResponse(MapRequest::RequestError requestError, QString sessionId, QString errorString = "", QString name = "");
    void setNewSessionResponse(QString sessiondId, QString publisherId, bool mprsSet = false, unsigned int mprs = 0);
    void setRenewSessionResponse();
    void setEndSessionResponse();
    void setAttachSessionResponse(QString sessionId, QString publisherId);
    void setPublishResponse(QString sessionId);
    void setSubscribeResponse(QString sessionId);
    void setPurgePublisherResponse(QString sessionId);

    void setSearchResults(QString sessionId, QList<SearchResult *> searchResults);

    void startPollResponse(QString sessionId);
    void addPollErrorResult(QString subName, MapRequest::RequestError error, QString errorString = "");
    void addPollResults(QList<SearchResult *> results, QString subName);
    void endPollResponse();

private:
    MapResponse(); // Don't use

    void checkAddSessionId(QString sessionId);
    void finishEnvelope();
    void startResponse();
    void endResponse();
    void writeIdentifier(Identifier id);

    void addLinkResult(Link link, QString metaXML);
    void addIdentifierResult(Identifier id, QString metaXML);
    void addMetadataResult(QString metaXML);

    void startSearchResult(SearchResult::ResultType resultType, QString subName);
    void endSearchResult();
private:
    const char *_soap_envelope;
    const char *_soap_encoding;
    MapRequest::RequestVersion _requestVersion;
    QXmlStreamWriter _xmlWriter;
    QBuffer _responseBuffer;
    QString _responseNamespace;
};

#endif // MAPRESPONSE_H
