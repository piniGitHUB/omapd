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

#include "identifier.h"
#include "metadata.h"

#define IFMAP_MAX_SIZE 100000;

static QString IFMAP_NS_1 = "http://www.trustedcomputinggroup.org/2006/IFMAP/1";
static QString IFMAP_META_NS_1 = "http://www.trustedcomputinggroup.org/2006/IFMAP-METADATA/1";

class SearchGraph
{
public:
    SearchGraph() {dirty = true;}
    QString name;
    bool dirty;

    Id startId;
    QString matchLinks;
    QString resultFilter;
    int maxDepth;
    int maxSize;
    QSet<Id> idList;
    QSet<Link> linkList;
    // Two SearchGraphs are equal iff their names are equal
    bool operator==(const SearchGraph &other) const;

    static QString translateFilter(QString ifmapFilter);
};

class MapGraph
{
public:
    MapGraph();

    void addMeta(Link key, QDomNodeList metaNodes, bool isLink, QString publisherId);
    Meta createAddReplaceMeta(QList<Meta> *existingMetaList, QString metaName, QString metaNS, Meta::Cardinality cardinality, QDomNode metaXML);
    void deleteMetaWithFilter(Link link, bool isLink, bool haveFilter, QString filter);

    void deleteMetaWithPublisherId(QString pubId);

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

    void dumpMap();
};

#endif // MAPGRAPH_H
