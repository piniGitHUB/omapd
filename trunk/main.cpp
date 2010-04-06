/*
main.cpp: Entry point of omapd

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

#include <QtCore/QCoreApplication>
#include <stdio.h>

#include "cmlserver.h"
#include "server.h"
#include "mapgraph.h"
#include "omapdconfig.h"

QFile logFile;
QFile logStderr;

void myMessageOutput(QtMsgType type, const char *msg)
{
    QByteArray bmsg(msg, qstrlen(msg));
    bmsg.append("\n");
    switch (type) {
    case QtDebugMsg:
    case QtWarningMsg:
    case QtCriticalMsg:
        if (logFile.isOpen()) {
            logFile.write(bmsg);
            logFile.flush();
        }
        if (logStderr.isOpen()) {
            logStderr.write(bmsg);
            logStderr.flush();
        }
        break;
    case QtFatalMsg:
        if (logFile.isOpen()) {
            logFile.write(bmsg);
            logFile.flush();
        }
        if (logStderr.isOpen()) {
            logStderr.write(bmsg);
            logStderr.flush();
        }
        abort();
    }
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    QString confFile("omapd.conf");
    if (argc == 2) {
        qDebug() << "main: will look for omapd configuration in:" << argv[1];
        confFile = QString(argv[1]);
    }

    OmapdConfig *omapdConfig = OmapdConfig::getInstance();
    if (omapdConfig->readConfigFile(confFile) < 0) {
        exit(-1);
    }

    if (omapdConfig->isSet("log_file_location")) {
        logFile.setFileName(omapdConfig->valueFor("log_file_location").toString().toAscii());
        QIODevice::OpenMode openMode = QIODevice::WriteOnly | QIODevice::Text;
        if (omapdConfig->valueFor("log_file_append").toBool())
            openMode |= QIODevice::Append;
        if (! logFile.open(openMode)) {
            qDebug() << "main: Error opening omapd log file:" << logFile.fileName();
            qDebug() << "main: |-->" << logFile.errorString();
        }
    }

    if (omapdConfig->valueFor("log_stderr").toBool()) {
        if (! logStderr.open(stderr, QIODevice::WriteOnly)) {
            qDebug() << "main: Error opening stderr for logging:" << logStderr.errorString();
        }
    }
    qInstallMsgHandler(myMessageOutput);

    qDebug() << "main: starting omapd on:" << QDateTime::currentDateTime().toString();

    omapdConfig->showConfigValues();

    //TODO: Threadpool the server objects and synchronize access to the MAP Graph

    MapGraph *mapGraph11 = new MapGraph();
    mapGraph11->addMetaNamespace(IFMAP_META_NS_1, "meta");
    mapGraph11->addMetaNamespace("http://www.trustedcomputinggroup.org/2006/IFMAP-HIRSCH/1", "hirsch");
    mapGraph11->addMetaNamespace("http://www.trustedcomputinggroup.org/2006/IFMAP-TRAPEZE/1", "trpz");
    mapGraph11->addMetaNamespace("http://www.trustedcomputinggroup.org/2006/IFMAP-SCADANET-METADATA/1", "scada");

    // Start a server with this MAP graph
    Server *server11 = new Server(mapGraph11);
    qDebug() << "Started server:" << server11;

    // Create a CML Server instance
    CmlServer *cmlServer = new CmlServer();
    cmlServer->setServer(server11);
    qDebug() << "Started CML Server:" << cmlServer;

    return a.exec();
}
