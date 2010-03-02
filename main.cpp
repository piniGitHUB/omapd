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

#include "server.h"
#include "mapgraph.h"

int main(int argc, char *argv[])
{
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
    server11->setDebug(Server::ShowXML | Server::ShowMAPGraphAfterChange | Server::ShowXMLFilterStatements);
    server11->setNonStandardBehavior(Server::EnablePubIdHint | Server::IgnoreSessionId);
    server11->setMapVersionSupport(Server::SupportIfmapV11);
    qDebug() << "Started server:" << server11;

    return a.exec();
}
