/*
clientparser.cpp: Implementation of ClientParser class

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

#include <QtNetwork>

#include "clientparser.h"
#include "mapgraph.h"
#include "mapsessions.h"

ClientParser::ClientParser(QObject *parent)
    : QObject(parent)
{
    _omapdConfig = OmapdConfig::getInstance();

    _xmlReader.setNamespaceProcessing(true);

    _requestError = MapRequest::ErrorNone;
    _requestVersion = MapRequest::VersionNone;
    _requestType = MapRequest::RequestNone;

    _clientSetSessionId = false;
    _sessionId = "";

    // Some clients (e.g. libifmap) don't send all the required namespaces
    // for Filters
    _namespaces.insert("hirsch", "http://www.trustedcomputinggroup.org/2006/IFMAP-HIRSCH/1");
    _namespaces.insert("trpz", "http://www.trustedcomputinggroup.org/2006/IFMAP-TRAPEZE/1");
    _namespaces.insert("scada", "http://www.trustedcomputinggroup.org/2006/IFMAP-SCADANET-METADATA/1");
    _namespaces.insert("meta", IFMAP_META_NS_1);

}

ClientParser::~ClientParser()
{
    const char *fnName = "ClientParser::~ClientParser:";
    qDebug() << fnName;
    _namespaces.clear();
    _mapRequest.clear();
}

void ClientParser::setSessionId(MapRequest &request)
{
    if (_requestVersion == MapRequest::IFMAPv11 && _clientSetSessionId) {
        request.setSessionId(_sessionId);
        request.setClientSetSessionId(true);
    }

    MapSessions::getInstance()->validateSessionId(request, (QTcpSocket *)_xmlReader.device());
    if (request.requestError()) {
        _requestError = request.requestError();
        _xmlReader.raiseError("Invalid Session Id");
    }
}

bool ClientParser::read(QTcpSocket *clientSocket)
{
    const char *fnName = "ClientHandler::read:";
    _xmlReader.setDevice(clientSocket);

    if (_xmlReader.readNextStartElement()) {
        if (_xmlReader.name().compare("Envelope", Qt::CaseInsensitive) == 0) {
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
                qDebug() << fnName << "Got SOAP Envelope"
                        << "in namespace:" << _xmlReader.namespaceUri();
            }
            registerMetadataNamespaces();
            readSoapEnvelope();

            _xmlReader.readNext();

        } else {
            qDebug() << fnName << "Error: Did not get a SOAP Envelope";
            _xmlReader.raiseError("Did not get a SOAP Envelope");
            _requestError = MapRequest::IfmapClientSoapFault;
        }
    }

    return !_xmlReader.error();
}

void ClientParser::readSoapEnvelope()
{
    const char *fnName = "ClientHandler::readSoapEnvelope:";
    while (_xmlReader.readNextStartElement() && !_xmlReader.hasError()) {
        if (_xmlReader.name().compare("Header", Qt::CaseInsensitive) == 0) {
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
                qDebug() << fnName << "Got SOAP Header"
                        << "in namespace:" << _xmlReader.namespaceUri();
            }
            registerMetadataNamespaces();
            readSoapHeader();
        } else if (_xmlReader.name().compare("Body", Qt::CaseInsensitive) == 0) {
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
                qDebug() << fnName << "Got SOAP Body"
                        << "in namespace:" << _xmlReader.namespaceUri();
            }
            registerMetadataNamespaces();
            readSoapBody();
        } else {
            qDebug() << fnName << "Error reading SOAP Header or Body:" << _xmlReader.name() << _xmlReader.tokenString();
            _xmlReader.raiseError("Error reading SOAP Header or Body");
            _requestError = MapRequest::IfmapClientSoapFault;
        }
    }
}

void ClientParser::readSoapHeader()
{
    while (_xmlReader.readNextStartElement() && !_xmlReader.hasError()) {
        if (_xmlReader.name() == "new-session" && _xmlReader.namespaceUri() == IFMAP_NS_1 &&
            _omapdConfig->valueFor("ifmap_version_support").value<OmapdConfig::MapVersionSupportOptions>().testFlag(OmapdConfig::SupportIfmapV10)) {
            // Support for IF-MAP 1.0 client new-session, but this is still IF-MAP 1.1 operations
            _requestVersion = MapRequest::IFMAPv11;
            readNewSession();
        } else if (_xmlReader.name() == "attach-session" && _xmlReader.namespaceUri() == IFMAP_NS_1 &&
                   _omapdConfig->valueFor("ifmap_version_support").value<OmapdConfig::MapVersionSupportOptions>().testFlag(OmapdConfig::SupportIfmapV10)) {
            // Support for IF-MAP 1.0 client attach-session, but this is still IF-MAP 1.1 operations
            _requestVersion = MapRequest::IFMAPv11;
            readAttachSession();
        } else if (_xmlReader.name() == "session-id" && _xmlReader.namespaceUri() == IFMAP_NS_1 &&
                   _omapdConfig->valueFor("ifmap_version_support").value<OmapdConfig::MapVersionSupportOptions>().testFlag(OmapdConfig::SupportIfmapV11)) {
            qDebug() << "reading session-id";
            _sessionId = _xmlReader.readElementText();
            _clientSetSessionId = true;
        } else {
            _xmlReader.skipCurrentElement();
        }
    }
}

void ClientParser::readSoapBody()
{
    while (_xmlReader.readNextStartElement() && !_xmlReader.hasError() &&
           _mapRequest.isNull()) {  // Make sure we only read the first request
        readMapRequest();
    }
    _xmlReader.readNext();
}

void ClientParser::readMapRequest()
{
    const char *fnName = "ClientHandler::readMapRequest:";

    QString method = _xmlReader.name().toString();
    QString methodNS = _xmlReader.namespaceUri().toString();
    if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
        qDebug() << fnName << "Got IF-MAP client request:" << method
                << "in namespace:" << methodNS;
    }

    if (methodNS == IFMAP_NS_1 &&
        _omapdConfig->valueFor("ifmap_version_support").value<OmapdConfig::MapVersionSupportOptions>().testFlag(OmapdConfig::SupportIfmapV11)) {
        _requestVersion = MapRequest::IFMAPv11;
    } else {
        // ERROR!!!
        qDebug() << fnName << "Error: Incorrect IF-MAP Namespace:" << methodNS;
        _requestError = MapRequest::IfmapClientSoapFault;
        _xmlReader.raiseError("Did not get a valid IF-MAP Namespace");
    }

    if (method == "new-session") {
        readNewSession();
    } else if (method == "attach-session") {
        readAttachSession();
    } else if (method == "newSession") {
        readNewSession();
    } else if (method == "publish") {
        registerMetadataNamespaces();
        readPublish();
    } else if (method == "subscribe") {
        registerMetadataNamespaces();
        readSubscribe();
    } else if (method == "search") {
        registerMetadataNamespaces();
        readSearch();
    } else if (method == "purgePublisher") {
        readPurgePublisher();
    } else if (method == "poll") {
        readPoll();
    } else {
        // ERROR!!!
        qDebug() << fnName << "Error reading element:" << _xmlReader.name();
        _requestError = MapRequest::IfmapClientSoapFault;
        _xmlReader.raiseError("Did not get a valid IF-MAP Request");
    }
}

void ClientParser::readNewSession()
{
    NewSessionRequest nsReq;
    nsReq.setRequestVersion(_requestVersion);
    _requestType = MapRequest::NewSession;

    _mapRequest.setValue(nsReq);
}

void ClientParser::readAttachSession()
{
    const char *fnName = "ClientHandler::readAttachSession:";
    AttachSessionRequest asReq;
    asReq.setRequestVersion(_requestVersion);
    _requestType = MapRequest::AttachSession;

    QString sessionId = _xmlReader.readElementText();
    if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
        qDebug() << fnName << "Got session-id in request:" << sessionId;
    }

    if (! sessionId.isEmpty()) {
        asReq.setSessionId(sessionId);
        asReq.setClientSetSessionId(true);

        _sessionId = sessionId;
        _clientSetSessionId = true;
    }

    MapSessions::getInstance()->validateSessionId(asReq, (QTcpSocket *)_xmlReader.device());
    if (asReq.requestError()) {
        _requestError = asReq.requestError();
    }

    _mapRequest.setValue(asReq);
}

void ClientParser::readPurgePublisher()
{
    const char *fnName = "ClientParser::readPurgePublisher:";

    PurgePublisherRequest ppReq;
    ppReq.setRequestVersion(_requestVersion);
    _requestType = MapRequest::PurgePublisher;

    setSessionId(ppReq);

    QString pubIdAttrName;
    if (_requestVersion == MapRequest::IFMAPv11) {
        pubIdAttrName = "publisher-id";
    }

    QXmlStreamAttributes attrs = _xmlReader.attributes();
    if (attrs.hasAttribute(pubIdAttrName)) {
        ppReq.setPublisherId(attrs.value(pubIdAttrName).toString());
        ppReq.setClientSetPublisherId(true);
    } else {
        qDebug() << fnName << "Error reading publisher-id in purgePublisher request";
        _xmlReader.raiseError("Error reading publisher-id in purgePublisher request");
        _requestError = MapRequest::IfmapClientSoapFault;
        ppReq.setRequestError(MapRequest::IfmapClientSoapFault);
    }

    _mapRequest.setValue(ppReq);
}

void ClientParser::readSubscribe()
{
    SubscribeRequest subReq;
    subReq.setRequestVersion(_requestVersion);
    _requestType = MapRequest::Subscribe;
    setSessionId(subReq);

    while (_xmlReader.readNextStartElement() && !subReq.requestError()) {
        readSubscribeOperation(subReq);
        _xmlReader.readNext();
    }
    _mapRequest.setValue(subReq);
}

void ClientParser::readSubscribeOperation(SubscribeRequest &subReq)
{
    SubscribeOperation subOperation;
    QXmlStreamAttributes attrs = _xmlReader.attributes();
    if (attrs.hasAttribute("name")) {
        subOperation.setName(attrs.value("name").toString());
    } else {
        _xmlReader.raiseError("Error reading subscription name");
        _requestError = MapRequest::IfmapClientSoapFault;
        subReq.setRequestError(MapRequest::IfmapClientSoapFault);
    }

    if (_xmlReader.name() == "update") {
        subOperation.setSubscribeType(SubscribeOperation::Update);
        subOperation.setSearch(parseSearch(subReq));
        subReq.addSubscribeOperation(subOperation);

        if (subReq.requestVersion() == MapRequest::IFMAPv11) {
            _xmlReader.readNextStartElement();
            _xmlReader.readNext();
        }
        _xmlReader.readNextStartElement();
        _xmlReader.readNext();

    } else if (_xmlReader.name() == "delete") {
        subOperation.setSubscribeType(SubscribeOperation::Delete);
        subReq.addSubscribeOperation(subOperation);
    } else {
        _xmlReader.raiseError("Error reading subscription operation");
        _requestError = MapRequest::IfmapClientSoapFault;
        subReq.setRequestError(MapRequest::IfmapClientSoapFault);
    }
}

void ClientParser::readSearch()
{
    SearchRequest searchReq;
    searchReq.setRequestVersion(_requestVersion);
    _requestType = MapRequest::Search;
    setSessionId(searchReq);

    searchReq.setSearch(parseSearch(searchReq));
    _mapRequest.setValue(searchReq);;
}

SearchType ClientParser::parseSearch(MapRequest &request)
{
    const char *fnName = "ClientHandler::parseSearch:";
    SearchType search;

    QXmlStreamAttributes attrs = _xmlReader.attributes();

    int maxDepth = 0;
    if (attrs.hasAttribute("max-depth")) {
        QString md = attrs.value("max-depth").toString();
        bool ok;
        maxDepth = md.toInt(&ok);
        if (ok) {
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
                qDebug() << fnName << "Got search parameter max-depth:" << maxDepth;
            }
            if (maxDepth < 0 && request.requestVersion() == MapRequest::IFMAPv11) {
                maxDepth = IFMAP_MAX_DEPTH_MAX;
            }
        } else {
            maxDepth = 0;
            qDebug() << fnName << "Got invalid search parameter max-depth:" << md;
            _xmlReader.raiseError("Error converting search attribute max-depth");
            _requestError = MapRequest::IfmapClientSoapFault;
            request.setRequestError(MapRequest::IfmapClientSoapFault);
        }
    } else {
        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
            qDebug() << fnName << "Using default search parameter max-depth:" << maxDepth;
        }
    }
    search.setMaxDepth(maxDepth);

    int maxSize = IFMAP_MAX_SIZE;
    if (attrs.hasAttribute("max-size")) {
        QString ms = attrs.value("max-size").toString();
        bool ok;
        maxSize = ms.toInt(&ok);
        if (ok) {
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
                qDebug() << fnName << "Got search parameter max-size:" << maxSize;
            }
            if (maxSize < 0 && request.requestVersion() == MapRequest::IFMAPv11) {
                maxSize = IFMAP_MAX_SIZE;
            }
        } else {
            maxSize = 0;
            qDebug() << fnName << "Got invalid search parameter max-size:" << ms;
            _xmlReader.raiseError("Error converting search attribute max-size");
            _requestError = MapRequest::IfmapClientSoapFault;
            request.setRequestError(MapRequest::IfmapClientSoapFault);
        }
    } else {
        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
            qDebug() << fnName << "Using default search parameter max-size:" << maxSize;
        }
    }
    search.setMaxSize(maxSize);

    if (attrs.hasAttribute("match-links")) {
        QString matchLinks = attrs.value("match-links").toString();
        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
            qDebug() << fnName << "Got search parameter match-links:" << matchLinks;
        }
        search.setMatchLinks(Subscription::translateFilter(matchLinks));
    } else {
        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
            qDebug() << fnName << "Using default search parameter match-links:" << search.matchLinks();
        }
    }

    if (attrs.hasAttribute("result-filter")) {
        QString resultFilter = attrs.value("result-filter").toString();
        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
            qDebug() << fnName << "Got search parameter result-filter:" << resultFilter;
        }
        search.setResultFilter(Subscription::translateFilter(resultFilter));
    } else {
        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
            qDebug() << fnName << "Using default search parameter result-filter:" << search.resultFilter();
        }
    }

    _xmlReader.readNextStartElement();
    if (_xmlReader.name() == "identifier" && request.requestVersion() == MapRequest::IFMAPv11) {
        _xmlReader.readNextStartElement();
    }
    Id startId = readIdentifier(request);
    if (request.requestError() == MapRequest::ErrorNone) {
        if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
            qDebug() << fnName << "Setting starting identifier:" << startId;
        }
        search.setStartId(startId);
    }

    // Finally set filterNamespaceDefinitions pulled out of SOAP Message
    search.setFilterNamespaceDefinitions(_namespaces);

    return search;
}

void ClientParser::readPoll()
{
    PollRequest pollReq;
    pollReq.setRequestVersion(_requestVersion);
    _requestType = MapRequest::Poll;
    setSessionId(pollReq);

    _mapRequest.setValue(pollReq);
}

void ClientParser::readPublish()
{
    PublishRequest pubReq;
    pubReq.setRequestVersion(_requestVersion);
    _requestType = MapRequest::Publish;
    setSessionId(pubReq);
    pubReq.setPublisherId(MapSessions::getInstance()->_activeSSRCSessions.key(pubReq.sessionId()));

    while (_xmlReader.readNextStartElement() && !pubReq.requestError()) {
        readPublishOperation(pubReq);
        _xmlReader.readNext();
    }

    _mapRequest.setValue(pubReq);
}

void ClientParser::readPublishOperation(PublishRequest &pubReq)
{
    QString pubOperationName = _xmlReader.name().toString();
    PublishOperation pubOperation;

    QXmlStreamAttributes attrs = _xmlReader.attributes();

    if (pubOperationName == "update") {
        pubOperation._publishType = PublishOperation::Update;
        if (pubReq.requestVersion() == MapRequest::IFMAPv11) {
            pubOperation._lifetime = Meta::LifetimeForever;
            pubOperation._clientSetLifetime = false;
        }

        bool isLink;
        pubOperation._link = readLink(pubReq, isLink);
        pubOperation._isLink = isLink;

        pubOperation._metadata = readMetadata(pubReq, pubOperation._lifetime);

    } else if (pubOperationName == "delete") {
        pubOperation._publishType = PublishOperation::Delete;
        if (attrs.hasAttribute("filter")) {
            pubOperation._deleteFilter = attrs.value("filter").toString();
            pubOperation._clientSetDeleteFilter = true;

            // TODO: make sure the application of the delete filter
            // does not result in a system error (from say a XMLQuery error)
            // that would render the entire publish operation invalid.
        }

        bool isLink;
        pubOperation._link = readLink(pubReq, isLink);
        pubOperation._isLink = isLink;
    } else {
        _xmlReader.raiseError("Error reading publish operation");
        _requestError = MapRequest::IfmapClientSoapFault;
        pubReq.setRequestError(MapRequest::IfmapClientSoapFault);
    }

    if (!pubReq.requestError()) {
        pubOperation._filterNamespaceDefinitions = _namespaces;
        pubReq.addPublishOperation(pubOperation);
    }
}

Link ClientParser::readLink(MapRequest &request, bool &isLink)
{
    const char *fnName = "ClientHandler::readLink:";
    Link key;
    Id id1;
    Id id2;
    int idCount = 0;

    _xmlReader.readNextStartElement();

    if (request.requestVersion() == MapRequest::IFMAPv11) {
        if (_xmlReader.name() == "link") {
            while (_xmlReader.readNextStartElement() && !_xmlReader.hasError()) {
                if (_xmlReader.name() == "identifier") {
                    if (_xmlReader.readNextStartElement()) {
                        if (idCount == 0) {
                            id1 = readIdentifier(request);
                            _xmlReader.readNext();
                            idCount++;
                        } else if (idCount == 1) {
                            id2 = readIdentifier(request);
                            _xmlReader.readNext();
                            idCount++;
                        }
                    } else {
                        qDebug() << fnName << "Error reading <identifier>:" << _xmlReader.name();
                        _xmlReader.raiseError("Invalid IF-MAP Structure");
                        _requestError = MapRequest::IfmapClientSoapFault;
                        request.setRequestError(MapRequest::IfmapClientSoapFault);
                    }
                    _xmlReader.readNext();
                }
                _xmlReader.readNext();
            }
        } else if (_xmlReader.name() == "identifier") {
            if (_xmlReader.readNextStartElement()) {
                if (idCount == 0) {
                    id1 = readIdentifier(request);
                    _xmlReader.readNext();
                    idCount++;
                }
            } else {
                qDebug() << fnName << "Error reading <identifier>:" << _xmlReader.name();
                _xmlReader.raiseError("Invalid IF-MAP Structure");
                _requestError = MapRequest::IfmapClientSoapFault;
                request.setRequestError(MapRequest::IfmapClientSoapFault);
            }
            _xmlReader.readNext();
        } else {
            qDebug() << fnName << "Error reading <link>:" << _xmlReader.name();
            _xmlReader.raiseError("Invalid IF-MAP Structure");
            _requestError = MapRequest::IfmapClientSoapFault;
            request.setRequestError(MapRequest::IfmapClientSoapFault);
        }

        _xmlReader.readNext();

    }

    if (request.requestError() == MapRequest::ErrorNone && idCount == 1) {
        key.first = id1;
        isLink = false;
    } else if (request.requestError() == MapRequest::ErrorNone && idCount == 2) {
        key = Identifier::makeLinkFromIds(id1, id2);
        isLink = true;
    }

    return key;
}

Id ClientParser::readIdentifier(MapRequest &request)
{
    const char *fnName = "ClientHandler::readIdentifier:";
    bool parseError = false;

    QString idName = _xmlReader.name().toString();
    QXmlStreamAttributes attrs = _xmlReader.attributes();
    QString ad = attrs.hasAttribute("administrative-domain") ?
                 attrs.value("administrative-domain").toString() :
                 QString();

    Identifier::IdType idType = Identifier::IdNone;
    QString value;
    QString other; // This is only for type Identifier::IdentityOther

    // TODO: Do some rudimentary type checking on the value, e.g.
    // (QHostAddress::setAddress ( const QString & address )) == true
    if (idName.compare("access-request") == 0) {
        idType = Identifier::AccessRequest;
        if (attrs.hasAttribute("name")) {
            idType = Identifier::AccessRequest;
            value = attrs.value("name").toString();
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
                qDebug() << fnName << "Got access-request name:" << value;
            }
        } else {
            // Error - did not specify access-request name
            parseError = true;
            request.setRequestError(MapRequest::IfmapInvalidIdentifier);
        }
    } else if (idName.compare("device") == 0) {
        _xmlReader.readNextStartElement();
        QString deviceType = _xmlReader.name().toString();
        if (deviceType.compare("aik-name") == 0 && request.requestVersion() == MapRequest::IFMAPv11) {
            idType = Identifier::DeviceAikName;
            value = _xmlReader.readElementText();
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
                qDebug() << fnName << "Got device aik-name:" << value;
            }
        } else if (deviceType.compare("name") == 0) {
            idType = Identifier::DeviceName;
            value = _xmlReader.readElementText();
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
                qDebug() << fnName << "Got device name:" << value;
            }
        } else {
            // Error - unknown device type
            parseError = true;
            request.setRequestError(MapRequest::IfmapInvalidIdentifier);
        }
    } else if (idName.compare("identity") == 0) {
        QString type;
        if (attrs.hasAttribute("type")) {
            type = attrs.value("type").toString();
            if (type.compare("aik-name") == 0) {
                idType = Identifier::IdentityAikName;
            } else if (type.compare("distinguished-name") == 0) {
                idType = Identifier::IdentityDistinguishedName;
            } else if (type.compare("dns-name") == 0) {
                idType = Identifier::IdentityDnsName;
            } else if (type.compare("email-address") == 0) {
                idType = Identifier::IdentityEmailAddress;
            } else if (type.compare("kerberos-principal") == 0) {
                idType = Identifier::IdentityKerberosPrincipal;
            } else if (type.compare("trusted-platform-module") == 0
                ) {
                idType = Identifier::IdentityTrustedPlatformModule;
            } else if (type.compare("username") == 0) {
                idType = Identifier::IdentityUsername;
            } else if (type.compare("sip-uri") == 0) {
                idType = Identifier::IdentitySipUri;
            } else if (type.compare("tel-uri") == 0) {
                idType = Identifier::IdentityTelUri;
            } else if (type.compare("other") == 0) {
                idType = Identifier::IdentityOther;
            } else {
                // Error - unknown identity type
                parseError = true;
                request.setRequestError(MapRequest::IfmapInvalidIdentifierType);
            }
        } else {
            // Error - did not specify identity type
            parseError = true;
            request.setRequestError(MapRequest::IfmapInvalidIdentifier);
        }

        if (attrs.hasAttribute("name")) {
            value = attrs.value("name").toString();
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
                qDebug() << fnName << "Got identity name:" << value;
            }
        } else {
            // Error - did not specify identity name attribute
            parseError = true;
            request.setRequestError(MapRequest::IfmapInvalidIdentifier);
        }

        if (idType == Identifier::IdentityOther) {
            if (attrs.hasAttribute("other-type-definition")) {
                // Append other-type-definition to value
                other = attrs.value("other-type-definition").toString();
                if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
                    qDebug() << fnName << "Got identity other-type-def:" << other;
                }
            } else {
                // Error - MUST have other-type-definition if idType is IdentityOther
                parseError = true;
                request.setRequestError(MapRequest::IfmapInvalidIdentifier);
            }
        }
    } else if (idName.compare("ip-address") == 0) {
        QString type;
        if (attrs.hasAttribute("type")) {
            type = attrs.value("type").toString();
            if (type.compare("IPv4") == 0) {
                idType = Identifier::IpAddressIPv4;
            } else if (type.compare("IPv6") == 0) {
                idType = Identifier::IpAddressIPv6;
            } else {
                // Error - did not correctly specify type
                parseError = true;
                request.setRequestError(MapRequest::IfmapInvalidIdentifier);
            }
        } else {
            idType = Identifier::IpAddressIPv4;
        }

        if (attrs.hasAttribute("value")) {
            value = attrs.value("value").toString();
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
                qDebug() << fnName << "Got ip-address:" << value;
            }
        } else {
            // Error - did not specify ip-address value attribute
            parseError = true;
            request.setRequestError(MapRequest::IfmapInvalidIdentifier);
        }

    } else if (idName.compare("mac-address") == 0) {
        idType = Identifier::MacAddress;

        if (attrs.hasAttribute("value")) {
            value = attrs.value("value").toString();
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
                qDebug() << fnName << "Got mac-address:" << value;
            }
        } else {
            // Error - did not specify mac-address value attribute
            parseError = true;
            request.setRequestError(MapRequest::IfmapInvalidIdentifier);
        }
    } else {
        // Error - unknown identifier name
        parseError = true;
        request.setRequestError(MapRequest::IfmapInvalidIdentifierType);
    }

    Id id;
    if (!parseError) {
        id.setType(idType);
        id.setAd(ad);
        id.setValue(value);
        id.setOther(other);
    } else {
        qDebug() << fnName << "Error parsing identifier";
        _requestError = request.requestError();
    }
    return id;
}

QList<Meta> ClientParser::readMetadata(PublishRequest &pubReq, Meta::Lifetime lifetime)
{
    const char *fnName = "ClientHandler::readMetadata:";

    QList<Meta> metaList;

    QString cardinalityAttrName = "cardinality", pubIdAttrName = "publisher-id", timestampAttrName = "timestamp";

    if (_requestVersion == MapRequest::IFMAPv11) {
        // To get past </identifier> or </link>
        _xmlReader.readNextStartElement();
    }

    QString allMetadata;
    if (_xmlReader.name() == "metadata") {
        while (_xmlReader.readNextStartElement() && !_xmlReader.hasError()) {
            QString metaNS = _xmlReader.namespaceUri().toString();
            QString metaName = _xmlReader.name().toString();
            QString metaQName = _xmlReader.qualifiedName().toString();
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
                qDebug() << fnName << "Got metadata element:" << metaQName << "in ns:" << metaNS;
            }
            
            if (metaNS.isEmpty()) {
                qDebug() << fnName << "Error: metadata element has no associated namespace:" << metaName;
                _requestError = MapRequest::IfmapInvalidMetadata;
                pubReq.setRequestError(MapRequest::IfmapInvalidMetadata);
            }

            // Local QXmlStreamWriter to add operational attributes
            QString metaString;
            QXmlStreamWriter xmlWriter(&metaString);
            xmlWriter.writeCurrentToken(_xmlReader);

            // Check for attributes to apply
            QXmlStreamAttributes elementAttrs = _xmlReader.attributes();

            Meta::Cardinality cardinalityValue;
            // Make sure we have the cardinality attribute and default it to multiValue
            if (elementAttrs.hasAttribute(cardinalityAttrName)) {
                cardinalityValue = (elementAttrs.value(cardinalityAttrName) == "singleValue")
                                   ? Meta::SingleValue : Meta::MultiValue;
            } else {
                qDebug() << fnName << "Notice: assigning metadata element multiValue cardinality:" << metaName;
                cardinalityValue = Meta::MultiValue;
                xmlWriter.writeAttribute(cardinalityAttrName, "multiValue");
            }

            // Set timestamp operational attribute
            QString ts = QDateTime::currentDateTime().toUTC().toString("yyyy-MM-ddThh:mm:ss");
            xmlWriter.writeAttribute(timestampAttrName, ts);
            // Set publisher-id operational attribute
            xmlWriter.writeAttribute(pubIdAttrName, pubReq.publisherId());

            _xmlReader.readNext();
            // While loop to recursively descend this metaName element, stopping when we get
            // to the closing metaName element (EndElement tokenType) or if we get an error
            while (!(_xmlReader.tokenType() == QXmlStreamReader::EndElement &&
                     _xmlReader.name() == metaName) && 
                   !_xmlReader.hasError()) {

                switch (_xmlReader.tokenType()) {
                case QXmlStreamReader::NoToken:
                case QXmlStreamReader::Invalid:
                case QXmlStreamReader::StartDocument:
                case QXmlStreamReader::EndDocument:
                case QXmlStreamReader::Comment:
                case QXmlStreamReader::DTD:
                case QXmlStreamReader::EntityReference:
                case QXmlStreamReader::ProcessingInstruction:
                    // NO-OP
                    break;
                case QXmlStreamReader::StartElement:
                case QXmlStreamReader::EndElement:
                case QXmlStreamReader::Characters:
                    xmlWriter.writeCurrentToken(_xmlReader);
                    break;
                }
                _xmlReader.readNext();
            }
            xmlWriter.writeCurrentToken(_xmlReader);

            if (_xmlReader.hasError()) {
                qDebug() << fnName << "Got an error:" << _xmlReader.errorString();
                pubReq.setRequestError(MapRequest::IfmapClientSoapFault);
                _requestError = MapRequest::IfmapClientSoapFault;
            }

            Meta aMeta(cardinalityValue, lifetime);
            aMeta.setElementName(metaName);
            aMeta.setElementNS(metaNS);
            aMeta.setPublisherId(pubReq.publisherId());
            aMeta.setMetaXML(metaString);
            if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
                qDebug() << fnName << "Seting xml for:" << metaName << "metaXML:" << aMeta.metaXML();
            }
            metaList << aMeta;

            allMetadata += metaString;
        }
        _xmlReader.readNext();
    } else {
        qDebug() << fnName << "Error reading <metadata>:" << _xmlReader.name();
        pubReq.setRequestError(MapRequest::IfmapClientSoapFault);
        _xmlReader.raiseError("Invalid IF-MAP Structure");
        _requestError = MapRequest::IfmapClientSoapFault;
    }

    // Can check metadata length here too
    if (_omapdConfig->valueFor("ifmap_debug_level").value<OmapdConfig::IfmapDebugOptions>().testFlag(OmapdConfig::ShowXMLParsing)) {
        qDebug() << fnName << "All metadata in request:" << endl << allMetadata;
    }

    return metaList;
}

void ClientParser::registerMetadataNamespaces()
{
    QXmlStreamNamespaceDeclarations nsVector = _xmlReader.namespaceDeclarations();
    for (int i=0; i<nsVector.size(); i++) {
        _namespaces.insert(nsVector.at(i).prefix().toString(), nsVector.at(i).namespaceUri().toString());
    }

}
