/*
omapdconfig.h: Declaration of OmapdConfig class

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
    enum IfmapDebug {
                DebugNone = 0x000,
                ShowClientOps = 0x0001,
                ShowXML = 0x0002,
                ShowHTTPHeaders = 0x0004,
                ShowHTTPState = 0x0008,
                ShowXMLParsing = 0x0010,
                ShowXMLFilterResults = 0x0020,
                ShowXMLFilterStatements = 0x0040,
                ShowMAPGraphAfterChange = 0x0080,
                ShowRawSocketData = 0x0100
               };
    Q_DECLARE_FLAGS(IfmapDebugOptions, IfmapDebug);
    static IfmapDebugOptions debugOptions(unsigned int dbgValue);
    static QString debugString(OmapdConfig::IfmapDebugOptions debug);

    enum MapVersionSupport {
               SupportNone = 0x00,
               SupportIfmapV10 = 0x01,
               SupportIfmapV11 = 0x02,
                           };
    Q_DECLARE_FLAGS(MapVersionSupportOptions, MapVersionSupport);
    static MapVersionSupportOptions mapVersionSupportOptions(unsigned int value);
    static QString mapVersionSupportString(OmapdConfig::MapVersionSupportOptions debug);

    static OmapdConfig* getInstance();

    bool isSet(QString key) { return _omapdConfig.contains(key); }
    QVariant valueFor(QString key);
    void showConfigValues();

    int readConfigFile(QString configFileName = "omapd.conf");

    void addConfigItem(QString key, QVariant value);
private:
    OmapdConfig(QObject * parent = 0);
    ~OmapdConfig();

    bool readConfigXML(QIODevice *device);

private:
    static OmapdConfig *_instance;

    QMap<QString,QVariant> _omapdConfig;
};
Q_DECLARE_OPERATORS_FOR_FLAGS(OmapdConfig::IfmapDebugOptions)
Q_DECLARE_OPERATORS_FOR_FLAGS(OmapdConfig::MapVersionSupportOptions)
Q_DECLARE_METATYPE(OmapdConfig::IfmapDebugOptions)
Q_DECLARE_METATYPE(OmapdConfig::MapVersionSupportOptions)

QDebug operator<<(QDebug dbg, OmapdConfig::IfmapDebugOptions & dbgOptions);
QDebug operator<<(QDebug dbg, OmapdConfig::MapVersionSupportOptions & dbgOptions);

#endif // OMAPDCONFIG_H
