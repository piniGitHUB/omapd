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

#include "server.h"
#include "omapdconfig.h"
#include "mapgraphinterface.h"

#if defined(Q_OS_WIN)
    #define _MAPGRAPH_PLUGIN_FILENAME "RAMHashTables.dll"
#else
    #define _MAPGRAPH_PLUGIN_FILENAME "libRAMHashTables.so"
#endif

QFile logFile;
QFile logStderr;

void myMessageOutput(QtMsgType type, const char *msg)
{
    QByteArray bmsg(msg, qstrlen(msg));
    bmsg.prepend(": ");
    bmsg.prepend(QDateTime::currentDateTime().toUTC().toString("yyyy-MM-ddThh:mm:ssZ").toAscii());
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

    QString pluginPath;
    if (omapdConfig->isSet("map_graph_plugin_path")) {
        pluginPath = omapdConfig->valueFor("map_graph_plugin_path").toString();
    } else {
        QDir pluginsDir(qApp->applicationDirPath());
#if defined(Q_OS_WIN)
        if (pluginsDir.dirName().toLower() == "debug" || pluginsDir.dirName().toLower() == "release")
            pluginsDir.cdUp();
#elif defined(Q_OS_MAC)
        if (pluginsDir.dirName() == "MacOS") {
            pluginsDir.cdUp();
            pluginsDir.cdUp();
            pluginsDir.cdUp();
        }
#endif
        pluginsDir.cd("plugins");
        pluginPath = pluginsDir.absoluteFilePath(_MAPGRAPH_PLUGIN_FILENAME);
    }

    qDebug() << "Will load plugin from:" << pluginPath;
    MapGraphInterface *mapGraph = 0;
     QPluginLoader pluginLoader(pluginPath);
     QObject *plugin = pluginLoader.instance();
     if (plugin) {
         mapGraph = qobject_cast<MapGraphInterface *>(plugin);
         if (!mapGraph) {
             qDebug() << "main: could not load MapGraph Plugin";
             exit(1);
         }
         if (omapdConfig->valueFor("debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowClientOps))
             mapGraph->setDebug(true);
         else
             mapGraph->setDebug(false);

     } else {
         qDebug() << "main: could not get plugin instance";
         exit(1);
     }

    // Start a server with this MAP graph
    Server *server = new Server(mapGraph);
    if (!server->startListening()) {
        qDebug() << __PRETTY_FUNCTION__ << ":" << "Could not start server";
        exit(2);
    }
    qDebug() << "Started server:" << server;

    return a.exec();
}
