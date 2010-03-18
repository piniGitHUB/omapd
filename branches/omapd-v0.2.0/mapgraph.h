/*
mapgraph.h: Definition of MapGraph and SearchGraph classes

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

#ifndef MAPGRAPH_H
#define MAPGRAPH_H

#include <QtCore>
#include <QtXml>
#include <qtsoap.h>

#include "identifier.h"
#include "metadata.h"

#define IFMAP_MAX_SIZE 100000;
#define IFMAP_MAX_DEPTH_MAX 10000;

static QString IFMAP_NS_1 = "http://www.trustedcomputinggroup.org/2006/IFMAP/1";
static QString IFMAP_META_NS_1 = "http://www.trustedcomputinggroup.org/2006/IFMAP-METADATA/1";

class SearchGraph
{
public:
    SearchGraph();
    QString name;
    Id startId;
    QString matchLinks;
    QString resultFilter;
    int maxDepth;
    int maxSize;
    QSet<Id> idList;
    QSet<Link> linkList;

    QtSoapStruct response;
    int curSize;
    bool hasErrorResult;
    bool sentFirstResult;

    // Two SearchGraphs are equal iff their names are equal
    bool operator==(const SearchGraph &other) const;

    static QString translateFilter(QString ifmapFilter);
    static QString intersectFilter(QString matchLinksFilter, QString resultFilter);
};

class MapGraph
{
public:
    MapGraph();

    void dumpMap();

    void addMeta(Link key, bool isLink, QList<Meta> publisherMeta, QString publisherId);
    bool deleteMetaWithPublisherId(QString pubId, QHash<Id, QList<Meta> > *idMetaDeleted, QHash<Link, QList<Meta> > *linkMetaDeleted, bool sessionMetaOnly = false);
    void replaceMeta(Link link, bool isLink, QList<Meta> newMetaList = QList<Meta>());

    // List of all identifiers that targetId is on a link with
    QList<Id> linksTo(Id targetId) { return _linksTo.values(targetId); }

    QList<Meta> metaForLink(Link link) { return _linkMeta.value(link); }
    QList<Meta> metaForId(Id id) { return _idMeta.value(id); }

private:
    QHash<Id, QList<Meta> > _idMeta; // Id --> all metadata on Id
    QHash<Link, QList<Meta> > _linkMeta;  // Link --> all metadata on Link
    QMultiHash<Id, Id> _linksTo;  // id1 --> id2 and id2 --> id1
    QMultiHash<QString, Id> _publisherIds;  // publisherId --> Id (useful for purgePublisher)
    QMultiHash<QString, Link> _publisherLinks;  // publisherId --> Link (useful for purgePublisher)
};

#endif // MAPGRAPH_H
