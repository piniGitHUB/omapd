/*
mapgraph.cpp: Implementation of MapGraph and SearchGraph classes

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

#include "mapgraph.h"

SearchResult::SearchResult(SearchResult::ResultType type, SearchResult::ResultScope scope)
    : _resultType(type), _resultScope(scope)
{
}

SearchResult::~SearchResult()
{
}

Subscription::Subscription(MapRequest::RequestVersion requestVersion)
    : _requestVersion(requestVersion)
{
    _sentFirstResult = false;
    _curSize = 0;
    _subscriptionError = MapRequest::ErrorNone;
}

Subscription::~Subscription()
{
    clearSearchResults();
}

void Subscription::clearSearchResults()
{
    while (! _searchResults.isEmpty()) {
        delete _searchResults.takeFirst();
    }

    _curSize = 0;
}

bool Subscription::operator==(const Subscription &other) const
{
    // Two SearchGraphs are equal iff their names are equal
    if (this->_name == other._name)
        return true;
    else
        return false;
}

QString Subscription::translateFilter(QString ifmapFilter)
{
    const char *fnName = "SearchGraph::translateFilter:";

    /* non-predicate expressions joined by "or" need to be translated
       into a parenthesized expression separated by "|".

       Examples:
       meta:ip-mac or scada:node
       --> (meta:ip-mac | scada:node)

       meta:role[@publisher-id = "myPubId" or name="myRole"] or meta:ip-mac
       --> (meta:role[@publisher-id = "myPubId" or name="myRole"] | meta:ip-mac)
    */

    // TODO: Do this with QRegExp

    QString qtFilter = ifmapFilter;
    if (ifmapFilter.contains("or", Qt::CaseInsensitive)) {
        qDebug() << fnName << "WARNING! filter translation is woefully incomplete!";
        qDebug() << fnName << "filter before translation:" << ifmapFilter;
        qtFilter = ifmapFilter.replace("or","|");
        qtFilter.prepend("(");
        qtFilter.append(")");
        qDebug() << fnName << "filter after translation:" << qtFilter;
    }

    return qtFilter;
}

QString Subscription::intersectFilter(QString matchLinksFilter, QString resultFilter)
{
    /* This method creates an intersect filter for XPath
       as the logical AND combination of the match-links
       filter and the result-filter.

       The passed-in filters MUST first individually be translated
       using SearchGraph::translateFilter().
    */
    QString qtFilter = "(";
    qtFilter += matchLinksFilter;
    qtFilter += " intersect ";
    qtFilter += resultFilter;
    qtFilter += ")";

    return qtFilter;
}

QStringList Subscription::filterPrefixes(QString filter)
{
    // TODO: Improve RegExp to not include colons inside quotes
    // For example: vend:ike-policy[@gateway=1.2.3.4 and meta:phase1/@identity=name:joe]
    // should not capture the `name' prefix.  However, it's only a slight performance hit
    // to capture these false prefixes, because they won't map to a declared namespace
    // in the document, or if they do, that's ok too.
    // Here's a possibility for a RegExp that excludes colons inside quotes, but not quite
    //QRegExp rx("([^\"{0}]\\b\\w+:)");

    // Look for a word boundary followed by 1 or more word characters up to a colon
    QRegExp rx("(\\b\\w+:)");
    QStringList prefixes;

    int pos = 0;
    while ((pos = rx.indexIn(filter, pos)) != -1) {
        QString prefix = rx.cap(1);
        prefixes << prefix.left(prefix.length()-1);
        pos += rx.matchedLength();
    }
    //qDebug() << "prefixes:" << prefixes.join("|");

    return prefixes;
}

MapGraph::MapGraph()
{
    _omapdConfig = OmapdConfig::getInstance();
}

void MapGraph::addMeta(Link link, bool isLink, QList<Meta> publisherMeta, QString publisherId)
{
    const char *fnName = "MapGraph::addMeta:";

    qDebug() << fnName << "number of metadata objects:" << publisherMeta.size();

    while (! publisherMeta.isEmpty()) {
        // All Metadata currently on identifier/link
        QList<Meta> existingMetaList;
        if (isLink) {
             existingMetaList = _linkMeta.take(link);
        } else {
             existingMetaList = _idMeta.take(link.first);
        }

        Meta newMeta = publisherMeta.takeFirst();
        // This matches metadata with same element name and element namespace
        int existingMetaIndex = existingMetaList.indexOf(newMeta);
        if (existingMetaIndex != -1) {
            if (newMeta.cardinality() == Meta::SingleValue) {
                // replace
                qDebug() << fnName << "Replacing singleValue meta:" << newMeta.elementName();
                existingMetaList.replace(existingMetaIndex, newMeta);
            } else {
                // add to list
                qDebug() << fnName << "Appending multiValue meta:" << newMeta.elementName();
                existingMetaList << newMeta;
            }
        } else {
            // no existing metadata of this type so add to list regardless of cardinality
            qDebug() << fnName << "Adding meta:" << newMeta.elementName();
            existingMetaList << newMeta;
        }

        if (isLink) {
            // Place updated metadata back on link
            _linkMeta.insert(link, existingMetaList);
        } else {
            // Place updated metadata back on identifier
            _idMeta.insert(link.first, existingMetaList);
        }
    }

    if (isLink) {        
        // Update lists of identifier linkages
        if (! _linksTo.contains(link.first, link.second)) _linksTo.insert(link.first, link.second);
        if (! _linksTo.contains(link.second, link.first)) _linksTo.insert(link.second, link.first);

        // Track links published by this publisherId
        if (! _publisherLinks.contains(publisherId, link)) _publisherLinks.insert(publisherId, link);

        qDebug() << fnName << "_linkMeta has size:" << _linkMeta.size();
    } else {
        // Track identifiers published by this publisherId
        if (! _publisherIds.contains(publisherId, link.first)) _publisherIds.insert(publisherId, link.first);

        qDebug() << fnName << "_idMeta has size:" << _idMeta.size();
    }
}

void MapGraph::replaceMeta(Link link, bool isLink, QList<Meta> newMetaList)
{
    //const char *fnName = "MapGraph::replaceMeta:";

    if (isLink) {
        // Remove metadata on link
        _linkMeta.remove(link);

        // Remove entries from _linksTo
        _linksTo.remove(link.first, link.second);
        _linksTo.remove(link.second, link.first);

        // Remove all publisherIds that published on this link
        QList<QString> pubIdsOnLink = _publisherLinks.keys(link);
        QListIterator<QString> pubIt(pubIdsOnLink);
        while (pubIt.hasNext()) {
            QString pubId = pubIt.next();
            _publisherLinks.remove(pubId, link);
        }

    } else {
        // Remove metadata on identifier
        _idMeta.remove(link.first);

        // Remove all publisherIds that published on this identifier
        QList<QString> pubIdsOnId = _publisherIds.keys(link.first);
        QListIterator<QString> pubIt(pubIdsOnId);
        while (pubIt.hasNext()) {
            QString pubId = pubIt.next();
            _publisherIds.remove(pubId, link.first);
        }
    }

    if (! newMetaList.isEmpty()) {
        if (isLink) {
            // Place updated metadata back on link
            _linkMeta.insert(link, newMetaList);

            // Update lists of identifier linkages
            if (! _linksTo.contains(link.first, link.second)) _linksTo.insert(link.first, link.second);
            if (! _linksTo.contains(link.second, link.first)) _linksTo.insert(link.second, link.first);

            QListIterator<Meta> metaIt(newMetaList);
            while (metaIt.hasNext()) {
                QString pubId = metaIt.next().publisherId();
                // Track links published by this publisherId
                if (! _publisherLinks.contains(pubId, link)) _publisherLinks.insert(pubId, link);
            }
        } else {
            // Place updated metadata back on identifier
            _idMeta.insert(link.first, newMetaList);

            QListIterator<Meta> metaIt(newMetaList);
            while (metaIt.hasNext()) {
                QString pubId = metaIt.next().publisherId();
                // Track identifiers published by this publisherId
                if (! _publisherIds.contains(pubId, link.first)) _publisherIds.insert(pubId, link.first);
            }
        }
    }
}

bool MapGraph::deleteMetaWithPublisherId(QString pubId, QHash<Id, QList<Meta> > *idMetaDeleted, QHash<Link, QList<Meta> > *linkMetaDeleted, bool sessionMetaOnly)
{
    const char *fnName = "MapGraph::deleteMetaWithPublisherId:";
    bool somethingDeleted = false;

    // Delete publisher's metadata on identifiers
    QList<Id> idsWithPub = _publisherIds.values(pubId);
    qDebug() << fnName << "have publisherId on num ids:" << idsWithPub.size();
    QListIterator<Id> idIt(idsWithPub);
    while (idIt.hasNext()) {
        Id idPub = idIt.next();
        QList<Meta> deletedMetaList;
        bool publisherHasMetaOnId = false;

        // Remove metadata on this identifier -- by definition this list in non-empty
        QList<Meta> metaOnId = _idMeta.take(idPub);
        qDebug() << fnName << "Examining metadata (" << metaOnId.size() << ") on id:" << idPub;
        for (int metaIndex = metaOnId.size()-1; metaIndex >= 0; metaIndex--) {
            QString testPubId = metaOnId.at(metaIndex).publisherId();

            if (pubId.compare(testPubId) == 0) {
                if (sessionMetaOnly) {
                    // Only delete session-level metadata
                    if (metaOnId.at(metaIndex).lifetime() == Meta::LifetimeSession) {
                        qDebug() << fnName << "Removed session identifier Meta:" << metaOnId.at(metaIndex).elementName();
                        deletedMetaList << metaOnId.takeAt(metaIndex);
                    } else {
                        // Not removing metadata for this publisher with lifetime=forever
                        publisherHasMetaOnId = true;
                    }
                } else {
                    // Delete metadata regardless of lifetime
                    qDebug() << fnName << "Removed identifier Meta:" << metaOnId.at(metaIndex).elementName();
                    deletedMetaList << metaOnId.takeAt(metaIndex);
                }
            }
        }

        // Keep track of deleted metadata
        if (! deletedMetaList.isEmpty()) {
            idMetaDeleted->insert(idPub, deletedMetaList);
            somethingDeleted = true;
        }

        // Replace remaining metadata on table of identifiers <--> metadata
        if (! metaOnId.isEmpty()) {
            _idMeta.insert(idPub, metaOnId);
        }

        // Update table of publisher <--> identifiers
        if (! publisherHasMetaOnId) {
            _publisherIds.remove(pubId, idPub);
        }
    }

    // Delete publisher's metadata on links
    QList<Link> linksWithPub = _publisherLinks.values(pubId);
    qDebug() << fnName << "have publisherId on num links:" << linksWithPub.size();
    QListIterator<Link> linkIt(linksWithPub);
    while (linkIt.hasNext()) {
        Link linkPub = linkIt.next();
        QList<Meta> deletedMetaList;
        bool publisherHasMetaOnLink = false;

        // Remove metadata on this link -- by definition this list is non-empty
        QList<Meta> metaOnLink = _linkMeta.take(linkPub);
        qDebug() << fnName << "Examining publisher metadata (" << metaOnLink.size() << ") on link:" << linkPub;
        for (int metaIndex = metaOnLink.size()-1; metaIndex >= 0; metaIndex--) {
            QString testPubId = metaOnLink.at(metaIndex).publisherId();

            if (pubId.compare(testPubId) == 0) {
                if (sessionMetaOnly) {
                    // Only delete session-level metadata
                    if (metaOnLink.at(metaIndex).lifetime() == Meta::LifetimeSession) {
                        qDebug() << fnName << "Removed session link Meta:" << metaOnLink.at(metaIndex).elementName();
                        deletedMetaList << metaOnLink.takeAt(metaIndex);
                    } else {
                        // Not removing metadata for this publisher with lifetime=forever
                        publisherHasMetaOnLink = true;
                    }
                } else {
                    // Delete metadata regardless of lifetime
                    qDebug() << fnName << "Removed link Meta:" << metaOnLink.at(metaIndex).elementName();
                    deletedMetaList << metaOnLink.takeAt(metaIndex);
                }
            }
        }

        // Keep track of deleted metadata
        if (! deletedMetaList.isEmpty()) {
            linkMetaDeleted->insert(linkPub, deletedMetaList);
            somethingDeleted = true;
        }

        if (metaOnLink.isEmpty()) {
            // Update list of identifier links
            _linksTo.remove(linkPub.first, linkPub.second);
            _linksTo.remove(linkPub.second, linkPub.first);
        } else {
            // Replace remaining metadata table of links <--> metadata
            _linkMeta.insert(linkPub, metaOnLink);
        }

        // Update table of publisher <--> links
        if (! publisherHasMetaOnLink) {
            _publisherLinks.remove(pubId, linkPub);
        }
    }

    return somethingDeleted;
}

void MapGraph::dumpMap()
{
    const char *fnName = "MapGraph::dumpMap:";
    qDebug() << fnName << "---------------------- start dump -------------------" << endl;

    QString idString;
    QTextStream idStream(&idString);

    qDebug() << fnName << "_idMeta has metadata on num identifiers:" << _idMeta.size();
    QHashIterator<Id, QList<Meta> > i(_idMeta);
    while (i.hasNext()) {
        i.next();
        Id id = i.key();
        QList<Meta> metaList = i.value();
        qDebug() << fnName << "Identifier metadata of length " << metaList.size() << endl << id;
        QListIterator<Meta> it(metaList);
        while (it.hasNext()) {
            Meta meta = it.next();
            idStream << meta.metaXML();
            QString metaXML = idStream.readAll();
            qDebug() << meta.lifetimeString() << "--->" <<  metaXML << endl;
        }
    }

    qDebug() << fnName << "_linkMeta has metadata on num links:" << _linkMeta.size();
    QHashIterator<Link, QList<Meta> > lm(_linkMeta);
    while (lm.hasNext()) {
        lm.next();
        Link link = lm.key();
        QList<Meta> metaList = lm.value();
        qDebug() << fnName << "Link metadata of length" << metaList.size() << endl << link;
        QListIterator<Meta> it(metaList);
        while (it.hasNext()) {
            Meta meta = it.next();
            idStream << meta.metaXML();
            QString metaXML = idStream.readAll();
            qDebug() << meta.lifetimeString() << "--->" <<  metaXML << endl;
        }
    }

    qDebug() << fnName << "---------------------- end dump -------------------" << endl;
}

void MapGraph::clearMap()
{
    const char *fnName = "MapGraph::clearMap:";
    qDebug() << fnName << "WARNING: clearing entire MAP contents!";
    _idMeta.clear();
    _linkMeta.clear();
    _linksTo.clear();
    _publisherIds.clear();
    _publisherLinks.clear();
}
