QT += network \
    xml \
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
    mapsessions.cpp
HEADERS += server.h \
    identifier.h \
    metadata.h \
    mapgraph.h \
    mapsessions.h
include(./qtsoap-2.6-opensource/src/qtsoap.pri)
