# Introduction #

There are numerous design constraints that come into play when starting a new software project.  Some of the driving factors in omapd design decisions are:
  * Platform neutral implementation
  * Leverage existing frameworks for XML, network, containers
  * Avoid the messiness and licensing issues of gSoap
  * Avoid the messiness of dealing with WSDLs
  * Focus on the data structures to represent MAP graphs

Prior to reading further, it may be a good idea to read through the IF-MAP specification.

# omapd MAP Graph #

## Identifiers and Links ##
In IF-MAP all identifiers and links exist by virtue of having metadata published on them, so really the identifiers and links are a way of organizing the metadata.  A link is just two identifiers with metadata associated with the link.  Therefore the data structures really just need to store metadata and associate it with identifiers and links.  This sounds like a hash table.

In order to use a hash table to associate identifiers and links with metadata, the hash table keys need to be unique.  In the IF-MAP v1.1 base schema, 5 top-level identifier types are defined; but many of these identifiers have sub-types.  So what makes an identifier unique?  It is a tuple of:
  * type
  * sub-type
  * value
  * administrative-domain (in most cases)
  * other type definition (in the case of `IdentityOther` type)

To make things easier, the identifier types and sub-types are flattened.  Then the unique hash key for an identifier is: type|value|administrative-domain|other.

Qt provides a QHash container class.  One QHash is used to hold associations of identifiers with metadata and another QHash is used to hold associations of links with metadata.

TNC published a set of identifiers that correspond with the TNC use case, but notionally any identifier schema can be used.  The key is the key - you just want something to uniquely associate the metadata, and provide some basic structure to the users of the MAP graph.  Future versions of omapd will not have TNC identifier schema restrictions, but it will certainly always support TNC identifier schema.

## Metadata ##
Metadata on a link or an identifier can be any XML!!!  TNC published a metadata schema for the TNC use case, but that's just one use case.  Each of the QHash containers that store metadata use a QList of Metadata objects.  There is an item in the QList of Metadata objects corresponding to each metadata type that has been published on that identifier or link.

Each Metadata object is a QList of DOM nodes containing the metadata XML.  If the metadata type is single-valued, the list of DOM nodes will always only have one node.  If the metadata type is multi-valued, the list of DOM nodes will have a node for every appended metadata of that type.

## Traversing the MAP Graph ##
Another data structure is used to traverse the MAP graph and describes all existing links (remember they exist by virtue of having metadata associated with them).  This link graph is realized with a QMultiHash container, which allows the same key (a source identifier) to map to several different values (target identifiers).  Since we must be able to traverse the entire MAP graph regardless of where we start, the QMultiHash link table has a key-->value mapping for each identifier, e.g. there are two insertions into the link table for each link created.

## Efficiently Tracking Publishers ##
There are several reasons to want to efficiently track which publishers are publishing which metadata:
  * purgePublisher operation
  * session timeouts removing metadata from a publisher
There are two QMultiHash tables for tracking publishers: one for tracking a publisher's metadata on identifiers, and another for tracking a publisher's metadata on links.  In each of these, the publisher-id is the key and the identifier or link is the value.

# omapd Server objects #
The omapd server is based on Qt's QTcpServer class.  The server needs to maintain a significant amount of state regarding MAP client connections, but this state is independent of the MAP graph.  Therefore the Server has containers to track:
  * Active SSRC sessions
  * Active ARC sessions
  * Active polls
  * Subscription lists

## Active SSRC Sessions ##
This is a QHash table of publisherId-->sessionId mappings.

## Active ARC Sessions ##
This is a QHash table of publisherId-->sessionId mappings.

## Active Polls ##
This is a QHash table of publisherId-->QTcpSocket mappings

## Subscription Lists ##
This is a QHash table of publisherId-->subscriptionList mappings

### Subscriptions ###
Subscriptions are sub-graphs about which a client expects to receive asynchronous notifications when metadata on this sub-graph changes.  Subscriptions are defined by searches, and thus the sub-graph class is named `SearchGraph`.  When a client subscribes (or searches), a sub-graph is created, which is a table of identifiers and a table of links (that have metadata associated with them).  However, a sub-graph does not also keep track of the actual metadata on the tables of links and identifiers - this duplicates too much data.

Whenever metadata is updated or deleted in a publish operation, all these sub-graphs must be checked.  If there is a change to the tables of links and identifiers, and those changes match the search parameters of the subscription, the sub-graph is marked as dirty.  Any outstanding polls are then checked to see if they have dirty sub-graphs and if so, search results are sent to the MAP client.

Since each sub-graph must be checked for each metadata publish operation, it is important that the lifecycle of a sub-graph be limited to the session of the MAP client.