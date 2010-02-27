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

bool SearchGraph::operator==(const SearchGraph &other) const
{
    // Two SearchGraphs are equal iff their names are equal
    if (this->name == other.name)
        return true;
    else
        return false;
}

QString SearchGraph::translateFilter(QString ifmapFilter)
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

MapGraph::MapGraph()
{
}

void MapGraph::addMeta(Link link, QDomNodeList metaNodes, bool isLink, bool republishing, QString publisherId)
{
    const char *fnName = "MapGraph::addMeta:";

    qDebug() << fnName << "number of metadata nodes:" << metaNodes.count();

    for (int i=0; i<metaNodes.count(); i++) {
        QString metaName = metaNodes.at(i).localName();
        QString metaNS = metaNodes.at(i).namespaceURI();
        QString cardinality = metaNodes.at(i).attributes().namedItem("cardinality").toAttr().value();
        Meta::Cardinality cardinalityValue = (cardinality == "singleValue") ? Meta::SingleValue : Meta::MultiValue;

        if (republishing) {
            // Get publisherId from metaNode
            publisherId = metaNodes.at(i).attributes().namedItem("publisher-id").toAttr().value();
        } else {
            // Add publisherId to meta node
            metaNodes.at(i).toElement().setAttribute("publisher-id",publisherId);
            // Add timestamp to meta node
            /* The dateTime is specified in the following form "YYYY-MM-DDThh:mm:ss" where:
                * YYYY indicates the year
                * MM indicates the month
                * DD indicates the day
                * T indicates the start of the required time section
                * hh indicates the hour
                * mm indicates the minute
                * ss indicates the second
                Note: All components are required!
            */
            metaNodes.at(i).toElement().setAttribute("timestamp",QDateTime::currentDateTime().toUTC().toString("yyyy-MM-ddThh:mm:ss"));
        }

        QDomNode metaDomNode = metaNodes.at(i);

        // All Metadata currently on identifier/link
        QList<Meta> existingMetaList;
        if (isLink) {
             existingMetaList = _linkMeta.take(link);
        } else {
             existingMetaList = _idMeta.take(link.first);
        }

        Meta meta = createAddReplaceMeta(&existingMetaList, metaName, metaNS, cardinalityValue, metaDomNode);
        existingMetaList << meta;

        if (isLink) {
            // Place updated metadata back on link
            _linkMeta.insert(link, existingMetaList);

            // Update lists of identifier linkages
            if (! _linksTo.contains(link.first, link.second)) _linksTo.insert(link.first, link.second);
            if (! _linksTo.contains(link.second, link.first)) _linksTo.insert(link.second, link.first);

            /* Track links published by this publisherId
               NB: this is inefficient in the for-loop when not republishing and working
               with multiple metaNodes - since the publisherId stays the same.
            */
            if (! _publisherLinks.contains(publisherId, link)) {
                _publisherLinks.insert(publisherId, link);
            }
        } else {
            // Place updated metadata back on identifier
            _idMeta.insert(link.first, existingMetaList);

            /* Track identifiers published by this publisherId
               NB: this is inefficient in the for-loop when not republishing and working
               with multiple metaNodes - since the publisherId stays the same.
            */
            if (! _publisherIds.contains(publisherId, link.first)) {
                _publisherIds.insert(publisherId, link.first);
            }
        }
    }

    if (isLink) {
        qDebug() << fnName << "_linkMeta has size:" << _linkMeta.size();
    } else {
        qDebug() << fnName << "_idMeta has size:" << _idMeta.size();
    }

    dumpMap();
}

Meta MapGraph::createAddReplaceMeta(QList<Meta> *existingMetaList, QString metaName, QString metaNS, Meta::Cardinality cardinality, QDomNode metaDomNode)
{
    const char *fnName = "MapGraph::createAddReplaceMeta:";
    Meta aMeta(cardinality);

    /*
    For each metadata, check if there is this elementName of metadata in the list.
    If this elementName is already on identifier, check cardinality.
    If singleValue, replace.
    If multiValue, append.
    */

    if (existingMetaList->isEmpty()) {
        // Easy - we will create new metadata
        qDebug() << fnName << "existingMetaList is empty";
        aMeta.addMetadataDomNode(metaDomNode);
        aMeta.setElementName(metaName);
        aMeta.setNamespace(metaNS);
    } else {
        // Harder - append (if multiValue), replace (if singleValue), or create (if DNE) metadata
        bool foundMatch = false;
        int index = 0;
        Meta metaMatch(cardinality);

        while (!foundMatch && index < existingMetaList->size()) {
            metaMatch = existingMetaList->at(index);
            if (metaMatch.elementName() == metaName && metaMatch.elementNS() == metaNS) {
                foundMatch = true;
            }
            index++;
        }
        index--;

        if (foundMatch && cardinality == Meta::MultiValue) {
            // found multiValue metadata - add to it
            qDebug() << fnName << "Adding to existing multiValue metadata";
            aMeta = existingMetaList->takeAt(index);
            aMeta.addMetadataDomNode(metaDomNode);
        } else if (foundMatch && cardinality == Meta::SingleValue) {
            // found singleValue metadata - replace it
            qDebug() << fnName << "Replacing existing singleValue metadata";
            existingMetaList->removeAt(index);
            aMeta.addMetadataDomNode(metaDomNode);
            aMeta.setElementName(metaName);
            aMeta.setNamespace(metaNS);
        } else {
            qDebug() << fnName << "Did not find existing metadata";
            aMeta.addMetadataDomNode(metaDomNode);
            aMeta.setElementName(metaName);
            aMeta.setNamespace(metaNS);
        }

    }

    return aMeta;
}

void MapGraph::replaceMetaNodes(Link link, bool isLink, QDomNodeList metaNodesToKeep)
{
    const char *fnName = "MapGraph::replaceMetaNodes:";

    // First delete existing metadata, then add it back on if there is any

    if (isLink) {
        // Don't need to remove entries from _linksTo, because we are either going to
        // put metaNodesToKeep back on link or remove the _linksTo entries later.

        // Remove all metadata from link
        _linkMeta.remove(link);

        // Remove all publisherIds that published on this link
        QList<QString> pubIdsOnLink = _publisherLinks.keys(link);
        QListIterator<QString> pubIt(pubIdsOnLink);
        while (pubIt.hasNext()) {
            QString pubId = pubIt.next();
            _publisherLinks.remove(pubId, link);
        }

    } else {
        // Remove all metadata from identifier
        _idMeta.remove(link.first);

        // Remove all publisherIds that published on this identifier
        QList<QString> pubIdsOnId = _publisherIds.keys(link.first);
        QListIterator<QString> pubIt(pubIdsOnId);
        while (pubIt.hasNext()) {
            QString pubId = pubIt.next();
            _publisherIds.remove(pubId, link.first);
        }
    }

    // Now that all existing metadata (and associated relationships) are deleted,
    // add it back.
    if (! metaNodesToKeep.isEmpty()) {
        addMeta(link, metaNodesToKeep, isLink, true);
    } else {
        if (isLink) {
            // Remove entries from _linksTo now that there is no metadata on link
            _linksTo.remove(link.first, link.second);
            _linksTo.remove(link.second, link.first);
            qDebug() << fnName << "All metadata deleted on link:" << link;
        } else {
            qDebug() << fnName << "All metadata deleted on identifier:" << link.first;
        }
        dumpMap();
    }
}

void MapGraph::deleteMetaWithPublisherId(QString pubId)
{
    const char *fnName = "MapGraph::deleteMetaWithPublisherId:";

    // Delete publisher's metadata on identifiers
    QList<Id> idsWithPub = _publisherIds.values(pubId);
    qDebug() << fnName << "have publisherId on num ids:" << idsWithPub.size();
    QListIterator<Id> idIt(idsWithPub);
    while (idIt.hasNext()) {
        Id idPub = idIt.next();
        qDebug() << fnName << "Will try to delete publisher metadata on id:" << idPub;

        // Get metadata on this identifier -- by definition this list in non-empty
        QList<Meta> metaForPublisher = _idMeta.value(idPub);
        QListIterator<Meta> metaIt(metaForPublisher);
        while (metaIt.hasNext()) {
            Meta aMeta = metaIt.next();
            QList<QDomNode> metaNodes = aMeta.metaDomNodes();
            // metaNodes list will have 1 item if singleValue, 1 or more if multiValue
            for (int index = 0; index < metaNodes.size(); index++) {
                // publisher-id attribute guaranteed to exist because I put in in there
                QString testPubId = metaNodes.at(index).attributes().namedItem("publisher-id").toAttr().value();
                if (testPubId == pubId) {
                    metaNodes.removeAt(index);
                }
            }

            if (metaNodes.isEmpty()) {
                // we removed one singleValue or all multiValue dom nodes
                metaForPublisher.removeOne(aMeta);
            }
        }

        // Update table of identifiers <--> metadata
        if (metaForPublisher.isEmpty()) {
            _idMeta.remove(idPub);
        } else {
            _idMeta.insert(idPub, metaForPublisher);
        }
    }
    // Update table of publisher <--> identifiers
    _publisherIds.remove(pubId);


    // Delete publisher's metadata on links
    QList<Link> linksWithPub = _publisherLinks.values(pubId);
    qDebug() << fnName << "have publisherId on num links:" << linksWithPub.size();
    QListIterator<Link> linkIt(linksWithPub);
    while (linkIt.hasNext()) {
        Link linkPub = linkIt.next();
        qDebug() << fnName << "Will try to delete publisher metadata on link:" << linkPub;

        // Get metadata on this link -- by definition this list is non-empty
        QList<Meta> metaForPublisher = _linkMeta.value(linkPub);
        QListIterator<Meta> metaIt(metaForPublisher);
        while (metaIt.hasNext()) {
            Meta aMeta = metaIt.next();
            QList<QDomNode> metaNodes = aMeta.metaDomNodes();
            // metaNodes list will have 1 item if singleValue, 1 or more if multiValue
            for (int index = 0; index < metaNodes.size(); index++) {
                // publisher-id guaranteed to exist because I put in in there
                QString testPubId = metaNodes.at(index).attributes().namedItem("publisher-id").toAttr().value();
                if (testPubId == pubId) {
                    metaNodes.removeAt(index);
                }
            }

            if (metaNodes.isEmpty()) {
                // we removed one singleValue or all multiValue dom nodes
                metaForPublisher.removeOne(aMeta);
            }
        }
        // Update table of links <--> metadata, and list of identifier links
        if (metaForPublisher.isEmpty()) {
            _linkMeta.remove(linkPub);
            _linksTo.remove(linkPub.first, linkPub.second);
            _linksTo.remove(linkPub.second, linkPub.first);
        } else {
            _linkMeta.insert(linkPub, metaForPublisher);
        }

    }
    // Update table of publisher <--> links
    _publisherLinks.remove(pubId);

    //dumpMap();
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
            QListIterator<QDomNode> mit(meta.metaDomNodes());
            while (mit.hasNext()) {
                idStream << mit.next();
            }
            QString metaXML = idStream.readAll();
            qDebug() << "--->" <<  metaXML << endl;
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
            QListIterator<QDomNode> mit(meta.metaDomNodes());
            while (mit.hasNext()) {
                idStream << mit.next();
            }
            QString metaXML = idStream.readAll();
            qDebug() << "--->" <<  metaXML << endl;
        }
    }

    qDebug() << fnName << "---------------------- end dump -------------------" << endl;
}
