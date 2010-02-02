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

    Meta(Meta::Cardinality cardinality = Meta::SingleValue);

    Meta::Cardinality cardinality() { return _cardinality; }
    QList<QDomNode> metaDomNodes() const { return _metaDomNodes; }
    QString elementName() const { return _elementName; }
    QString elementNS() const { return _elementNS; }

    void addMetadataDomNode(QDomNode metaNode) { _metaDomNodes << metaNode; }
    void setElementName(QString elementName) { _elementName = elementName; }
    void setNamespace(QString ns) { _elementNS = ns; }

    // Two Meta objects are equal iff their elementName and namespace members are the same
    bool operator==(const Meta &other) const;

private:
    Meta::Cardinality _cardinality;
    QString _elementName;
    QString _elementNS;
    QList<QDomNode> _metaDomNodes;
};

#endif // METADATA_H
