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
#include <stdlib.h>

#include "cmlserver.h"
#include "server.h"
#include "mapgraph.h"

FILE *file;

void myMessageOutput(QtMsgType type, const char *msg)
{
     switch (type) {
     case QtDebugMsg:
         fprintf(stderr, "%s\n", msg);
         fprintf(file, "omapd: %s\n", msg);
         fflush(file);
         break;
     case QtWarningMsg:
         fprintf(stderr, "Warning: %s\n", msg);
         break;
     case QtCriticalMsg:
         fprintf(stderr, "Critical: %s\n", msg);
         break;
     case QtFatalMsg:
         fprintf(stderr, "Fatal: %s\n", msg);
         abort();
     }
}

int main(int argc, char *argv[])
{
    file = fopen("omapd.log", "a");
    if (file) {
        qInstallMsgHandler(myMessageOutput);
    }
    qDebug() << "main: starting omapd on:" << QDateTime::currentDateTime().toString();

    QCoreApplication a(argc, argv);

    /*
    TODO: Load run-time options
        * address, port
        * SSL on/off
        *    key, cert, CA
        * debug level
        * how to enforce MAY and SHOULD sections in SPEC
        * enable/disable non-standard features
    */


    //TODO: Threadpool the server objects and synchronize access to the MAP Graph

    MapGraph *mapGraph11 = new MapGraph();
    // Start a server with this MAP graph
    Server *server11 = new Server(mapGraph11, 8081);
    //server11->setDebug(Server::ShowHTTPState | Server::ShowXML | Server::ShowXMLFilterResults | Server::ShowXMLFilterStatements);
    server11->setDebug(Server::ShowXML | Server::ShowMAPGraphAfterChange | Server::ShowHTTPHeaders | Server::ShowClientOps);
    server11->setNonStandardBehavior(Server::IgnoreSessionId);
    server11->setMapVersionSupport(Server::SupportIfmapV11 | Server::SupportIfmapV10);
    server11->setServerCapability(Server::CreateClientConfigs);
    if (! server11->getServerCapability().testFlag(Server::PatchedQtForNamespaceReporting)) {
        mapGraph11->addMetaNamespace(IFMAP_META_NS_1, "meta");
        mapGraph11->addMetaNamespace("http://www.trustedcomputinggroup.org/2006/IFMAP-HIRSCH/1", "hirsch");
        mapGraph11->addMetaNamespace("http://www.trustedcomputinggroup.org/2006/IFMAP-TRAPEZE/1", "trpz");
        mapGraph11->addMetaNamespace("http://www.trustedcomputinggroup.org/2006/IFMAP-SCADANET-METADATA/1", "scada");
    }
    qDebug() << "Started server:" << server11;

    // Create a CML Server instance
    CmlServer *cmlServer = new CmlServer(8080);
    cmlServer->setDebug(CmlServer::ShowClientOps | CmlServer::ShowHTTPHeaders | CmlServer::ShowRawSocketData);
    cmlServer->setServerCapability(CmlServer::DisableClientCertVerify);
    cmlServer->setServer(server11);
    qDebug() << "Started CML Server:" << cmlServer;

    return a.exec();
}
