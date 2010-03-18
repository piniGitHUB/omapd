/*
metadata.h: Definition of Meta Class

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

#ifndef METADATA_H
#define METADATA_H

#include <QtCore>
#include <QtXml>

class Meta
{
public:
    enum Cardinality {
                SingleValue = 0,
                MultiValue
            };

    enum Lifetime {
                LifetimeSession = 0,
                LifetimeForever
    };

    enum PublishOperationType {
                PublishUpdate = 0,
                PublishDelete
    };

    Meta(Meta::Cardinality cardinality = Meta::SingleValue,
         Meta::Lifetime lifetime = Meta::LifetimeSession);

    Meta::Cardinality cardinality() { return _cardinality; }
    Meta::Lifetime lifetime() const { return _lifetime; }
    QString lifetimeString();

    QDomNode metaNode() const { return _metaNode; }
    QString elementName() const { return _elementName; }
    QString elementNS() const { return _elementNS; }
    QString publisherId() const { return _publisherId; }

    void setMetaNode(QDomNode metaNode) { _metaNode = metaNode; }
    void setElementName(QString elementName) { _elementName = elementName; }
    void setNamespace(QString ns) { _elementNS = ns; }
    void setLifetime(Meta::Lifetime lifetime) { _lifetime = lifetime; }
    void setPublisherId(QString pubId) { _publisherId = pubId; }

    // Two Meta objects are equal iff their elementName and namespace members are the same
    bool operator==(const Meta &other) const;

private:
    Meta::Cardinality _cardinality;
    Meta::Lifetime _lifetime;
    QString _publisherId;
    QString _elementName;
    QString _elementNS;
    QDomNode _metaNode;
};

#endif // METADATA_H
