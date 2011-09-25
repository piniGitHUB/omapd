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
    mapsessions.cpp \
    cmlserver.cpp \
    omapdconfig.cpp \
    clientparser.cpp \
    maprequest.cpp \
    mapresponse.cpp \
    subscription.cpp
HEADERS += server.h \
    identifier.h \
    metadata.h \
    mapsessions.h \
    cmlserver.h \
    omapdconfig.h \
    clientparser.h \
    maprequest.h \
    mapresponse.h \
    subscription.h \
    mapgraphinterface.h
