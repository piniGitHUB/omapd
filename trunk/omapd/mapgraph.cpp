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

MapGraph::MapGraph()
{
}

void MapGraph::addMeta(Link link, QDomNodeList metaNodes, bool isLink, QString publisherId)
{
    const char *fnName = "MapGraph::addMeta:";

    qDebug() << fnName << "number of metadata nodes:" << metaNodes.count();

    QString idString;
    QTextStream idStream(&idString);

    for (int i=0; i<metaNodes.count(); i++) {
        QString metaName = metaNodes.at(i).localName();
        QString metaNS = metaNodes.at(i).namespaceURI();
        QString cardinality = metaNodes.at(i).attributes().namedItem("cardinality").toAttr().value();
        Meta::Cardinality cardinalityValue = (cardinality == "singleValue") ? Meta::SingleValue : Meta::MultiValue;

        // Add publisherId to meta node
        metaNodes.at(i).toElement().setAttribute("publisher-id",publisherId);
        // Add timestamp to meta node
        // TODO: Make sure timestamp is of correct type per IF-MAP spec
        metaNodes.at(i).toElement().setAttribute("timestamp",QDateTime::currentDateTime().toString("dd.MM.yyyy hh:mm:ss"));

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

        } else {
            // Place updated metadata back on identifier
            _idMeta.insert(link.first, existingMetaList);
        }
    }

    if (isLink) {
        // Track links published by this publisherId
        if (! _publisherLinks.contains(publisherId, link)) {
            _publisherLinks.insert(publisherId, link);
        }

        qDebug() << fnName << "_idLink has size:" << _linkMeta.size();
    } else {
        // Track identifiers published by this publisherId
        if (! _publisherIds.contains(publisherId, link.first)) {
            _publisherIds.insert(publisherId, link.first);
        }

        qDebug() << fnName << "_idMeta has size:" << _idMeta.size();
    }

    //dumpMap();
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

void MapGraph::deleteMetaWithFilter(Link link, bool isLink, bool haveFilter, QString filter)
{
    const char *fnName = "MapGraph::deleteMetaWithFilter:";
    if (isLink) {
        if (!haveFilter || (filter.compare("*") == 0)) {
            // IF-MAP: if filter is not given, delete all metadata

            // Easy - just delete all metadata on Identifier
            _linkMeta.remove(link);

            // Also delete entries from _publisherLinks list for this Link
            QList<QString> publishersOnLink = _publisherLinks.keys(link);
            QListIterator<QString> pubIt(publishersOnLink);
            while (pubIt.hasNext()) {
                QString pubId = pubIt.next();
                _publisherLinks.remove(pubId, link);
            }

            // Also delete entries from _linksTo table, since deleting all meta on this link
            _linksTo.remove(link.first, link.second);
            _linksTo.remove(link.second, link.first);

        } else if (haveFilter && filter.isEmpty()) {
            // IF-MAP: if filter is empty string, do nothing
            qDebug() << fnName << "Empty filter string given --> nothing deleted";
        } else {
            // Harder - apply filter
            // TODO - apply filter ;-)
        }

    } else {
        if (!haveFilter || (filter.compare("*") == 0)) {
            // IF-MAP: if filter is not given, delete all metadata

            // Easy - just delete all metadata on Identifier
            _idMeta.remove(link.first);

            // Also delete entries from _publisherIds list for this Identifier
            QList<QString> publishersOnId = _publisherIds.keys(link.first);
            QListIterator<QString> pubIt(publishersOnId);
            while (pubIt.hasNext()) {
                QString pubId = pubIt.next();
                _publisherIds.remove(pubId, link.first);
            }
        } else if (haveFilter && filter.isEmpty()) {
            // IF-MAP: if filter is empty string, do nothing
            qDebug() << fnName << "Empty filter string given --> nothing deleted";
        } else {
            // Harder - apply filter
            // TODO - apply filter ;-)
        }
    }

    //dumpMap();
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

QSet<Link> MapGraph::matchLinksAtId(Id targetId, QString matchLinks)
{
    const char *fnName = "MapGraph::matchLinks:";
    QSet<Link > idMatchList;

    // List of all identifiers that targetId is on a link with
    QList<Id> matchIds = _linksTo.values(targetId);

    QListIterator<Id> idIter(matchIds);
    while (idIter.hasNext()) {
        // matchId is the other end of the link
        Id matchId = idIter.next();
        // Get identifier-order independent link
        Link link = Identifier::makeLinkFromIds(targetId, matchId);
        // Get metadata on this link
        QList<Meta> curLinkMeta = _linkMeta.value(link);
        //If any of this metadata matches matchLinks add link to idMatchList
        if (metadataPassesFilter(curLinkMeta, matchLinks)) {
            qDebug() << fnName << "Adding link:" << link;
            idMatchList.insert(link);
        }
    }

    return idMatchList;
}

bool MapGraph::metadataPassesFilter(QList<Meta> metaList, QString filter)
{
    bool foundMatch = false;

    return true;

    // TODO: implement filtering
    QListIterator<Meta> it(metaList);
    while (it.hasNext() && !foundMatch) {
        Meta aMeta = it.next();
        // This is the simplest possible application of the filter for proof of concept
        // and needs to be worked out according to IF-MAP spec
        if (aMeta.elementName() == filter) {
            foundMatch = true;
        }
    }

    return foundMatch;
}

QList<Meta> MapGraph::metaForLink(Link link)
{
    return _linkMeta.value(link);
}

QList<Meta> MapGraph::metaForId(Id id)
{
    return _idMeta.value(id);
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
            //qDebug() << "--->" << meta.metadataXML().join("\n") << endl;
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
            //qDebug() << "--->" << meta.metadataXML().join("\n") << endl;
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
