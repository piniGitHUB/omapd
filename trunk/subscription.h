/*
subscription.h: Declaration of SearchResult and Subscribtion Classes

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

#ifndef SUBSCRIPTION_H
#define SUBSCRIPTION_H

#include "metadata.h"
#include "identifier.h"
#include "maprequest.h"

class SearchType;

class SearchResult {
public:
    enum ResultType {
        SearchResultType = 1,
#ifdef IFMAP20
        UpdateResultType,
        DeleteResultType,
        NotifyResultType
#endif //IFMAP20
    };

    enum ResultScope {
        IdentifierResult = 1,
        LinkResult
    };

#ifdef IFMAP20
    static SearchResult::ResultType resultTypeForPublishType(Meta::PublishOperationType publishType);
#endif //IFMAP20

    SearchResult(SearchResult::ResultType type, SearchResult::ResultScope scope);
    ~SearchResult();

    SearchResult::ResultType _resultType;
    SearchResult::ResultScope _resultScope;
    Link _link;
    Id _id;
    QString _metadata;
    MapRequest::RequestError _error;
};

class Subscription
{
public:
    Subscription(MapRequest::RequestVersion requestVersion);
    ~Subscription();

    QString _name;
    SearchType _search;

    QSet<Id> _idList;
    QSet<Link> _linkList;

    QList<SearchResult *> _searchResults;
#ifdef IFMAP20
    QList<SearchResult *> _deltaResults;
#endif //IFMAP20
    int _curSize;
    bool _sentFirstResult;
    MapRequest::RequestError _subscriptionError;
    MapRequest::RequestVersion _requestVersion;

    // Two SearchGraphs are equal iff their names are equal
    bool operator==(const Subscription &other) const;

    void clearSearchResults();

    static QString translateFilter(QString ifmapFilter);
    static QString intersectFilter(QString matchLinksFilter, QString resultFilter);
    static QStringList filterPrefixes(QString filter);
};

#endif // SUBSCRIPTION_H
