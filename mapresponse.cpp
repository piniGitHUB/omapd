/*
mapresponse.cpp: Implementation of MapResponse class

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

#include "mapresponse.h"
#include "maprequest.h"

// Constructor used for building intermediate results
MapResponse::MapResponse(MapRequest::RequestVersion reqVersion)
    : _requestVersion(reqVersion)
{
    _responseNamespace = MapRequest::requestVersionNamespace(reqVersion);

    _responseBuffer.open(QIODevice::WriteOnly);
    _xmlWriter.setDevice(&_responseBuffer);
    _xmlWriter.setAutoFormatting(true);
    _xmlWriter.setAutoFormattingIndent(2);

    // Write <SOAP-ENV:Envelope> opening tag and necessary namespaces
    _xmlWriter.writeStartDocument();
    _xmlWriter.writeNamespace(SOAPv11_ENVELOPE, "SOAP-ENV");
    _xmlWriter.writeStartElement(SOAPv11_ENVELOPE,"Envelope");
    _xmlWriter.writeNamespace(SOAPv11_ENCODING, "SOAP-ENC");
    _xmlWriter.writeNamespace(XML_SCHEMA_INSTANCE, "xsi");
    _xmlWriter.writeNamespace(XML_SCHEMA,"xsd");
    if (reqVersion != MapRequest::VersionNone) {
        // Don't include ifmap namespace for SOAP-ENV:Fault
        _xmlWriter.writeNamespace(_responseNamespace,"ifmap");
    }
    // At this point _xmlWriter is ready for <SOAP-ENV:Header> or <SOAP-ENV:Body>
}

MapResponse::~MapResponse()
{
    _responseBuffer.close();
}

void MapResponse::finishEnvelope()
{
    _xmlWriter.writeEndElement(); // End 'Envelope' element
    _xmlWriter.writeEndDocument();
}

void MapResponse::startResponse()
{
    _xmlWriter.writeStartElement(SOAPv11_ENVELOPE, "Body");
    _xmlWriter.writeStartElement(_responseNamespace, "response");
}

void MapResponse::endResponse()
{
    _xmlWriter.writeEndElement(); // </ifmap:response>
    _xmlWriter.writeEndElement(); // </SOAP-ENV:Body>
}

void MapResponse::checkAddSessionId(QString sessionId)
{
    if (_requestVersion == MapRequest::IFMAPv11) {
        _xmlWriter.writeStartElement(SOAPv11_ENVELOPE, "Header");
        _xmlWriter.writeTextElement(IFMAP_NS_1, "session-id", sessionId);
        _xmlWriter.writeEndElement(); // </SOAP-ENV:Header>
    }
}

void MapResponse::writeIdentifier(Identifier id)
{
    if (_requestVersion == MapRequest::IFMAPv11) {
        _xmlWriter.writeStartElement("identifier");
    }

    switch (id.type()) {
    case Identifier::IdNone:
        break;
    case Identifier::AccessRequest:
        _xmlWriter.writeEmptyElement("access-request");
        _xmlWriter.writeAttribute("name", id.value());
        break;
    case Identifier::DeviceAikName:
        _xmlWriter.writeStartElement("device");
        _xmlWriter.writeTextElement("aik-name",id.value());
        _xmlWriter.writeEndElement(); // </device>
        break;
    case Identifier::DeviceName:
        _xmlWriter.writeStartElement("device");
        _xmlWriter.writeTextElement("name",id.value());
        _xmlWriter.writeEndElement(); // </device>
        break;
    case Identifier::IpAddressIPv4:
        _xmlWriter.writeEmptyElement("ip-address");
        _xmlWriter.writeAttribute("value", id.value());
        _xmlWriter.writeAttribute("type", "IPv4");
        break;
    case Identifier::IpAddressIPv6:
        _xmlWriter.writeEmptyElement("ip-address");
        _xmlWriter.writeAttribute("value", id.value());
        _xmlWriter.writeAttribute("type", "IPv6");
        break;
    case Identifier::MacAddress:
        _xmlWriter.writeEmptyElement("mac-address");
        _xmlWriter.writeAttribute("value", id.value());
        break;
    case Identifier::IdentityAikName:
        _xmlWriter.writeEmptyElement("identity");
        _xmlWriter.writeAttribute("name", id.value());
        _xmlWriter.writeAttribute("type", "aik-name");
        break;
    case Identifier::IdentityDistinguishedName:
        _xmlWriter.writeEmptyElement("identity");
        _xmlWriter.writeAttribute("name", id.value());
        _xmlWriter.writeAttribute("type", "distinguished-name");
        break;
    case Identifier::IdentityDnsName:
        _xmlWriter.writeEmptyElement("identity");
        _xmlWriter.writeAttribute("name", id.value());
        _xmlWriter.writeAttribute("type", "dns-name");
        break;
    case Identifier::IdentityEmailAddress:
        _xmlWriter.writeEmptyElement("identity");
        _xmlWriter.writeAttribute("name", id.value());
        _xmlWriter.writeAttribute("type", "email-address");
        break;
    case Identifier::IdentityKerberosPrincipal:
        _xmlWriter.writeEmptyElement("identity");
        _xmlWriter.writeAttribute("name", id.value());
        _xmlWriter.writeAttribute("type", "kerberos-principal");
        break;
    case Identifier::IdentityTrustedPlatformModule:
        _xmlWriter.writeEmptyElement("identity");
        _xmlWriter.writeAttribute("name", id.value());
        _xmlWriter.writeAttribute("type", "trusted-platform-module");
        break;
    case Identifier::IdentityUsername:
        _xmlWriter.writeEmptyElement("identity");
        _xmlWriter.writeAttribute("name", id.value());
        _xmlWriter.writeAttribute("type", "username");
        break;
    case Identifier::IdentitySipUri:
        _xmlWriter.writeEmptyElement("identity");
        _xmlWriter.writeAttribute("name", id.value());
        _xmlWriter.writeAttribute("type", "sip-uri");
        break;
#ifdef IFMAP20
    case Identifier::IdentityHipHit:
        _xmlWriter.writeEmptyElement("identity");
        _xmlWriter.writeAttribute("name", id.value());
        _xmlWriter.writeAttribute("type", "hip-hit");
        break;
#endif //IFMAP20
    case Identifier::IdentityTelUri:
        _xmlWriter.writeEmptyElement("identity");
        _xmlWriter.writeAttribute("name", id.value());
        _xmlWriter.writeAttribute("type", "tel-uri");
        break;
    case Identifier::IdentityOther:
        _xmlWriter.writeEmptyElement("identity");
        _xmlWriter.writeAttribute("name", id.value());
        _xmlWriter.writeAttribute("type", "other");
        _xmlWriter.writeAttribute("other-type-definition", id.other());
        break;
    }

    if ( id.type() != Identifier::DeviceAikName && id.type() != Identifier::DeviceName
         //&& (id.type() != Identifier::AccessRequest || _requestVersion == MapRequest::IFMAPv11)
         && !(id.ad().isEmpty()) ) {
        _xmlWriter.writeAttribute("administrative-domain", id.ad());
    }

    if (_requestVersion == MapRequest::IFMAPv11) {
        _xmlWriter.writeEndElement(); // </identifier>
    }
}

void MapResponse::setClientFault(QString faultString)
{
    _xmlWriter.writeStartElement(SOAPv11_ENVELOPE, "Body");
    _xmlWriter.writeStartElement(SOAPv11_ENVELOPE, "Fault");
    _xmlWriter.writeTextElement("Faultstring", faultString);
    _xmlWriter.writeTextElement("Faultcode", "SOAP-ENV:Client");
    _xmlWriter.writeEndElement(); // </SOAP-ENV:Fault>
    _xmlWriter.writeEndElement(); // </SOAP-ENV:Body>
    finishEnvelope();
}

void MapResponse::setErrorResponse(MapRequest::RequestError requestError, QString sessionId, QString errorString, QString name)
{
    checkAddSessionId(sessionId);
    startResponse();
    _xmlWriter.writeStartElement("errorResult");
    _xmlWriter.writeAttribute("errorCode", MapRequest::requestErrorString(requestError));
    if (! name.isEmpty()) {
        _xmlWriter.writeAttribute("name", name);
    }
    if (! errorString.isEmpty()) {
        _xmlWriter.writeTextElement("errorString",errorString);
    }
    _xmlWriter.writeEndElement(); // </errorResult>
    endResponse();
    finishEnvelope();
}

#ifdef IFMAP20
void MapResponse::setNewSessionResponse(QString sessionId, QString publisherId, bool mprsSet, unsigned int mprs)
#else
void MapResponse::setNewSessionResponse(QString sessionId, QString publisherId)
#endif //IFMAP20
{
    if (_requestVersion == MapRequest::IFMAPv11) {
        _xmlWriter.writeStartElement(SOAPv11_ENVELOPE, "Header");
        _xmlWriter.writeTextElement(IFMAP_NS_1, "session-id", sessionId);
        _xmlWriter.writeTextElement(IFMAP_NS_1, "publisher-id", publisherId);
        _xmlWriter.writeEndElement(); // </SOAP-ENV:Header>

        _xmlWriter.writeStartElement(SOAPv11_ENVELOPE, "Body");
        _xmlWriter.writeTextElement(IFMAP_NS_1, "session-id", sessionId);
        _xmlWriter.writeTextElement(IFMAP_NS_1, "publisher-id", publisherId);
        _xmlWriter.writeEndElement(); // </SOAP-ENV:Body>
#ifdef IFMAP20
    } else if (_requestVersion == MapRequest::IFMAPv20) {
        startResponse();
        _xmlWriter.writeStartElement("newSessionResult");
        _xmlWriter.writeAttribute("session-id", sessionId);
        _xmlWriter.writeAttribute("ifmap-publisher-id", publisherId);
        if (mprsSet) {
            QString mprsStr;
            mprsStr.setNum(mprs);
            _xmlWriter.writeAttribute("max-poll-result-size", mprsStr);
        }
        _xmlWriter.writeEndElement(); // </newSessionResult>
        endResponse();
#endif //IFMAP20
    }

    finishEnvelope();
}

#ifdef IFMAP20
void MapResponse::setRenewSessionResponse()
{
    startResponse();
    _xmlWriter.writeEmptyElement("renewSessionResult");
    endResponse();
    finishEnvelope();
}

void MapResponse::setEndSessionResponse()
{
    startResponse();
    _xmlWriter.writeEmptyElement("endSessionResult");
    endResponse();
    finishEnvelope();
}
#endif //IFMAP20

void MapResponse::setAttachSessionResponse(QString sessionId, QString publisherId)
{
    _xmlWriter.writeStartElement(SOAPv11_ENVELOPE, "Header");
    _xmlWriter.writeTextElement(IFMAP_NS_1, "session-id", sessionId);
    _xmlWriter.writeTextElement(IFMAP_NS_1, "publisher-id", publisherId);
    _xmlWriter.writeEndElement(); // </SOAP-ENV:Header>

    _xmlWriter.writeStartElement(SOAPv11_ENVELOPE, "Body");
    _xmlWriter.writeTextElement(IFMAP_NS_1, "session-id", sessionId);
    _xmlWriter.writeTextElement(IFMAP_NS_1, "publisher-id", publisherId);
    _xmlWriter.writeEndElement(); // </SOAP-ENV:Body>
    finishEnvelope();
}

void MapResponse::setPublishResponse(QString sessionId)
{
    checkAddSessionId(sessionId);
    startResponse();
    _xmlWriter.writeEmptyElement("publishReceived");
    endResponse();
    finishEnvelope();
}

void MapResponse::setSubscribeResponse(QString sessionId)
{
    checkAddSessionId(sessionId);
    startResponse();
    _xmlWriter.writeEmptyElement("subscribeReceived");
    endResponse();
    finishEnvelope();
}

void MapResponse::setPurgePublisherResponse(QString sessionId)
{
    checkAddSessionId(sessionId);
    startResponse();
    _xmlWriter.writeEmptyElement("purgePublisherReceived");
    endResponse();
    finishEnvelope();
}

void MapResponse::setSearchResults(QString sessionId, QList<SearchResult *> searchResults)
{
    checkAddSessionId(sessionId);
    startResponse();

    _xmlWriter.writeStartElement("searchResult");

    QListIterator<SearchResult *> srIt(searchResults);
    while (srIt.hasNext()) {
        SearchResult *result = srIt.next();
        switch (result->_resultScope) {
        case SearchResult::IdentifierResult:
            addIdentifierResult(result->_id, result->_metadata);
            break;
        case SearchResult::LinkResult:
            addLinkResult(result->_link, result->_metadata);
            break;
        }
    }

    _xmlWriter.writeEndElement(); // </searchResult>

    endResponse();
    finishEnvelope();
}

void MapResponse::addLinkResult(Link link, QString metaXML)
{
    if (_requestVersion == MapRequest::IFMAPv11) {
        _xmlWriter.writeStartElement("linkResult");
        writeIdentifier(link.first);
        writeIdentifier(link.second);
        if (! metaXML.isEmpty()) {
            addMetadataResult(metaXML);
        }
        _xmlWriter.writeEndElement(); // </linkResult>
#ifdef IFMAP20
    } else if (_requestVersion == MapRequest::IFMAPv20) {
        _xmlWriter.writeStartElement("resultItem");
        writeIdentifier(link.first);
        writeIdentifier(link.second);
        if (! metaXML.isEmpty()) {
            addMetadataResult(metaXML);
        }
        _xmlWriter.writeEndElement(); // </resultItem>
#endif //IFMAP20
    }
}

void MapResponse::addIdentifierResult(Identifier id, QString metaXML)
{
    if (_requestVersion == MapRequest::IFMAPv11) {
        _xmlWriter.writeStartElement("identifierResult");
        writeIdentifier(id);
        if (! metaXML.isEmpty()) {
            addMetadataResult(metaXML);
        }
        _xmlWriter.writeEndElement(); // </identifierResult>
#ifdef IFMAP20
    } else if (_requestVersion == MapRequest::IFMAPv20) {
        _xmlWriter.writeStartElement("resultItem");
        writeIdentifier(id);
        if (! metaXML.isEmpty()) {
            addMetadataResult(metaXML);
        }
        _xmlWriter.writeEndElement(); // </resultItem>
#endif //IFMAP20
    }
}

void MapResponse::addMetadataResult(QString metaXML)
{
    // TODO: It would be cleaner to just write the <metadata> tags here
    // instead of adding them in Server::filteredMetadata(), but if I do that
    // only the first metadata node gets written.
    // TODO: The metadata namespace definitions should be in the individual
    // metadata nodes, not in the <metadata> element
    // TODO: It _may_ be better if the namespace prefixes matched the prefixes
    // used in the client request
    //_xmlWriter.writeStartElement("metadata");
    QXmlStreamReader xmlReader(metaXML);
    while (!xmlReader.atEnd()) {
        xmlReader.readNext();
        switch (xmlReader.tokenType()) {
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
            _xmlWriter.writeCurrentToken(xmlReader);
            break;
        }
    }
    //_xmlWriter.writeEndElement(); // </metadata>
}

void MapResponse::startPollResponse(QString sessionId)
{
    checkAddSessionId(sessionId);
    startResponse();
    _xmlWriter.writeStartElement("pollResult");
}

void MapResponse::addPollErrorResult(QString subName, MapRequest::RequestError error, QString errorString)
{
    _xmlWriter.writeStartElement("errorResult");
    _xmlWriter.writeAttribute("errorCode", MapRequest::requestErrorString(error));
    _xmlWriter.writeAttribute("name", subName);
    if (! errorString.isEmpty()) {
        _xmlWriter.writeTextElement("errorString",errorString);
    }
    _xmlWriter.writeEndElement(); // </errorResult>
}

void MapResponse::addPollResults(QList<SearchResult *> results, QString subName)
{
    QListIterator<SearchResult *> srIt(results);

    // Only want to write the <searchResult> start tag if there are actually any
    // <searchResult> elements to write.
    bool startedSearchResult = false;

    // First get all SearchResult::SearchResultType results for <searchResult>.
    // Breaking it up because a client receives <searchResult> elements only after the
    // first poll, but there could be <notifyResult> elements in there too.
    while (srIt.hasNext()) {
        SearchResult *result = srIt.next();

        if (result->_resultType == SearchResult::SearchResultType) {
            if (!startedSearchResult) {
                // We only have one <searchResult> per subscription
                startSearchResult(result->_resultType, subName);
                startedSearchResult = true;
            }
            switch (result->_resultScope) {
            case SearchResult::IdentifierResult:
                addIdentifierResult(result->_id, result->_metadata);
                break;
            case SearchResult::LinkResult:
                addLinkResult(result->_link, result->_metadata);
                break;
            }
        }
    }
    // Write the </searchResult> closing tag if we wrote the opening one
    if (startedSearchResult) {
        endSearchResult();
    }

    // Rewind the iterator
    srIt.toFront();

    // Next get all the <updateResult>, <deleteResult>, and <notifyResult> results
    while (srIt.hasNext()) {
        SearchResult *result = srIt.next();

        if (result->_resultType != SearchResult::SearchResultType) {
            startSearchResult(result->_resultType, subName);

            switch (result->_resultScope) {
            case SearchResult::IdentifierResult:
                addIdentifierResult(result->_id, result->_metadata);
                break;
            case SearchResult::LinkResult:
                addLinkResult(result->_link, result->_metadata);
                break;
            }

            endSearchResult();
        }
    }
}

void MapResponse::endPollResponse()
{
    _xmlWriter.writeEndElement(); // </pollResult>
    endResponse();
    finishEnvelope();
}

void MapResponse::startSearchResult(SearchResult::ResultType resultType, QString subName)
{
    QString tagName = "";
    switch (resultType) {
    case SearchResult::SearchResultType:
        tagName = "searchResult";
        break;
#ifdef IFMAP20
    case SearchResult::UpdateResultType:
        tagName = "updateResult";
        break;
    case SearchResult::DeleteResultType:
        tagName = "deleteResult";
        break;
    case SearchResult::NotifyResultType:
        tagName = "notifyResult";
        break;
#endif //IFMAP20
   }

    _xmlWriter.writeStartElement(tagName);
    _xmlWriter.writeAttribute("name", subName);
}

void MapResponse::endSearchResult() {
    _xmlWriter.writeEndElement();
}
