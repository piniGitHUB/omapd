/*
maprequest.h: Declaration of IF-MAP Request classes

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

#ifndef MAPREQUEST_H
#define MAPREQUEST_H

#include <QList>
#include <QString>
#include "identifier.h"
#include "metadata.h"
#include "omapdconfig.h"

static QString IFMAP_NS_1 = "http://www.trustedcomputinggroup.org/2006/IFMAP/1";
static QString IFMAP_META_NS_1 = "http://www.trustedcomputinggroup.org/2006/IFMAP-METADATA/1";

#define IFMAP_MAX_SIZE 100000;
#define IFMAP_MAX_DEPTH_MAX 10000;

class MapRequest
{
public:
    enum RequestVersion {
        VersionNone = 0,
        IFMAPv11,
    };

    enum RequestType {
        RequestNone = 0,
        NewSession,
        AttachSession,
        Publish,
        Subscribe,
        Search,
        PurgePublisher,
        Poll
    };

    enum ValidationType {
        ValidationNone = 0,
        ValidationBaseOnly,
        ValidationMetadataOnly,
        ValidationAll
    };

    enum RequestError {
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
        IfmapSystemError // Server error
    };
    
    MapRequest(MapRequest::RequestType requestType = MapRequest::RequestNone);
    MapRequest(const MapRequest&);
    ~MapRequest() {;}

    static QString requestTypeString(MapRequest::RequestType reqType);
    static QString requestVersionString(MapRequest::RequestVersion version);
    static QString requestVersionNamespace(MapRequest::RequestVersion version);
    static QString requestErrorString(MapRequest::RequestError error);

    MapRequest::RequestError requestError() const { return _requestError; }
    MapRequest::RequestVersion requestVersion() const { return _requestVersion; }
    MapRequest::RequestType requestType() const { return _requestType; }
    QString sessionId() const { return _sessionId; }
    bool clientSetSessionId() const { return _clientSetSessionId; }

    void setRequestError(MapRequest::RequestError requestError) { _requestError = requestError; }
    void setRequestType(MapRequest::RequestType requestType) { _requestType = requestType; }
    void setRequestVersion(MapRequest::RequestVersion requestVersion) { _requestVersion = requestVersion; }
    void setSessionId(QString sessionId) { _sessionId = sessionId; }
    void setClientSetSessionId(bool set) { _clientSetSessionId = set; }

protected:
    MapRequest::RequestError _requestError;
    MapRequest::RequestVersion _requestVersion;
    MapRequest::RequestType _requestType;
    QString _sessionId;
    bool _clientSetSessionId;
};

class NewSessionRequest : public MapRequest
{
public:
    NewSessionRequest();
    NewSessionRequest(const NewSessionRequest&);
    ~NewSessionRequest() {;}
};
Q_DECLARE_METATYPE(NewSessionRequest)

class AttachSessionRequest : public MapRequest
{
public:
    AttachSessionRequest();
    AttachSessionRequest(const AttachSessionRequest&);
    ~AttachSessionRequest() {;}
};
Q_DECLARE_METATYPE(AttachSessionRequest)

class PurgePublisherRequest : public MapRequest
{
public:
    PurgePublisherRequest();
    PurgePublisherRequest(const PurgePublisherRequest&);
    ~PurgePublisherRequest() {;}
    const PurgePublisherRequest& operator= (const PurgePublisherRequest& rhs);

    QString publisherId() const { return _publisherId; }
    bool clientSetPublisherId() const { return _clientSetPublisherId; }
    void setPublisherId(QString pubId) { _publisherId = pubId; }
    void setClientSetPublisherId(bool set) { _clientSetPublisherId = set; }
private:
    QString _publisherId;
    bool _clientSetPublisherId;
};
Q_DECLARE_METATYPE(PurgePublisherRequest)

class PublishOperation
{
public:
    enum PublishType {
        None = 0,
        Update,
        Delete
    };

    PublishOperation();
    ~PublishOperation();

    PublishOperation::PublishType _publishType;
    Link _link;
    bool _isLink;
    QList<Meta> _metadata;

    Meta::Lifetime _lifetime;
    bool _clientSetLifetime;

    QString _deleteFilter;
    bool _clientSetDeleteFilter;
    QMap<QString, QString> _filterNamespaceDefinitions;
};

class PublishRequest : public MapRequest
{
public:
    PublishRequest();
    PublishRequest(const PublishRequest&);
    ~PublishRequest() { _publishOperations.clear();}

    QString publisherId() const { return _publisherId; }
    void setPublisherId(QString pubId) { _publisherId = pubId; }
    QList<PublishOperation> publishOperations() const { return _publishOperations; }
    void addPublishOperation(PublishOperation pubOper) { _publishOperations.append(pubOper); }
private:
    QList<PublishOperation> _publishOperations;
    QString _publisherId;
};
Q_DECLARE_METATYPE(PublishRequest)

class SearchType
{
public:
    SearchType();
    int maxDepth() const { return _maxDepth; }
    int maxSize() const { return _maxSize; }
    QString resultFilter() const { return _resultFilter; }
    QString matchLinks() const { return _matchLinks; }
    Id startId() const { return _startId; }
    QMap<QString, QString> filterNamespaceDefinitions() const { return _filterNamespaceDefinitions; }

    bool clientSetMaxDepth() const { return _clientSetMaxDepth; }
    bool clientSetMaxSize() const { return _clientSetMaxSize; }
    bool clientSetResultFilter() const { return _clientSetResultFilter; }
    bool clientSetMatchLinks() const { return _clientSetMatchLinks; }

    void setMaxDepth(int maxDepth) { _maxDepth = maxDepth; _clientSetMaxDepth = true; }
    void setMaxSize(int maxSize) { _maxSize = maxSize; _clientSetMaxSize = true; }
    void setResultFilter(QString resultFilter) { _resultFilter = resultFilter; _clientSetResultFilter = true; }
    void setMatchLinks(QString matchLinks) { _matchLinks = matchLinks; _clientSetMatchLinks = true; }
    void setStartId(Id id) { _startId = id; }
    void setFilterNamespaceDefinitions(QMap<QString,QString> nsDefs) {_filterNamespaceDefinitions = nsDefs; }
protected:
    int _maxDepth;
    bool _clientSetMaxDepth;
    int _maxSize;
    bool _clientSetMaxSize;
    QString _resultFilter;
    bool _clientSetResultFilter;
    QString _matchLinks;
    bool _clientSetMatchLinks;
    Id _startId;
    QMap<QString, QString> _filterNamespaceDefinitions;
};

class SubscribeOperation
{
public:
    enum SubscribeType {
        Update,
        Delete
    };

    SubscribeOperation();

    void setName(QString name) { _name = name; }
    QString name() const { return _name; }

    SubscribeOperation::SubscribeType subscribeType() const { return _subscribeType; }
    void setSubscribeType(SubscribeOperation::SubscribeType subType) { _subscribeType = subType; }

    SearchType search() const { return _search; }
    void setSearch(SearchType search) { _search = search; }
private:
    QString _name;
    SubscribeOperation::SubscribeType _subscribeType;
    SearchType _search;
};

class SearchRequest : public MapRequest
{
public:
    SearchRequest();
    SearchRequest(const SearchRequest&);
    ~SearchRequest() {;}

    SearchType search() const { return _search; }
    void setSearch(SearchType search) { _search = search; }
private:
    SearchType _search;
};
Q_DECLARE_METATYPE(SearchRequest)

class SubscribeRequest : public MapRequest
{
public:
    SubscribeRequest();
    SubscribeRequest(const SubscribeRequest&);
    ~SubscribeRequest() { _subscribeOperations.clear();}

    QList<SubscribeOperation> subscribeOperations() const { return _subscribeOperations; }
    void addSubscribeOperation(SubscribeOperation subOper) { _subscribeOperations.append(subOper); }
private:
    QList<SubscribeOperation> _subscribeOperations;
};
Q_DECLARE_METATYPE(SubscribeRequest)

class PollRequest : public MapRequest
{
public:
    PollRequest();
    PollRequest(const PollRequest&);
    ~PollRequest() {;}
};
Q_DECLARE_METATYPE(PollRequest)

#endif // MAPREQUEST_H
