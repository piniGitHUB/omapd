QT += network \
    xmlpatterns
QT -= gui
TARGET = omapd
CONFIG += console
CONFIG += debug
CONFIG -= app_bundle
TEMPLATE = app
SOURCES += main.cpp \
    server.cpp \
    identifier.cpp \
    metadata.cpp \
    mapgraph.cpp \
    mapsessions.cpp \
    cmlserver.cpp \
    omapdconfig.cpp \
    clientparser.cpp \
    maprequest.cpp \
    mapresponse.cpp
HEADERS += server.h \
    identifier.h \
    metadata.h \
    mapgraph.h \
    mapsessions.h \
    cmlserver.h \
    omapdconfig.h \
    clientparser.h \
    maprequest.h \
    mapresponse.h
