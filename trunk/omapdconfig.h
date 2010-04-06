/*
omapdconfig.h: Definition of OmapdConfig class

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

#ifndef OMAPDCONFIG_H
#define OMAPDCONFIG_H

#include <QtCore>

class OmapdConfig : public QObject
{
    Q_OBJECT
public:
    static OmapdConfig* getInstance();

    bool isSet(QString key) { return _omapdConfig.contains(key); }
    QVariant valueFor(QString key);
    void showConfigValues();

    int readConfigFile(QString configFileName = "omapd.conf");

    void addConfigItem(QString key, QVariant value);
private:
    OmapdConfig(QObject * parent = 0);
    bool readConfigXML(QIODevice *device);
private:
    static OmapdConfig *_instance;

    QMap<QString,QVariant> _omapdConfig;
};

#endif // OMAPDCONFIG_H
