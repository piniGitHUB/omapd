omapd is an open source IF-MAP Server.  It currently implements the IF-MAP v1.1 and v2.0 specifications published by the Trusted Computing Group (TCG).

IF-MAP is a HTTPS/SOAP interface with publish/subscribe/search semantics.  It was created as part of the Trusted Network Connect (TNC) family of network-security-focused specifications as a way for networked devices to coordinate security metadata, thus its name: Metadata Access Point (MAP).

Even though IF-MAP was written for the TNC use case, there are many other potential applications of IF-MAP.  Think of IF-MAP as Twitter for networked devices.  Do you have a collection of devices that need a place to coordinate metadata, and receive asynchronous notifications when metadata they are interested in changes, and do so in a way that does not have any pre-imposed datastore schema restrictions?  IF-MAP may be for you!

omapd is written in C++ using the Qt Framework from Nokia.  Qt was chosen for its excellent network, XML, and container classes; multi-platform support; and LGPL licensing.

NEWS!!!
As of omapd-0.7.0, omapd has passed TCG IF-MAP Compliance Testing. Here is the  [official announcement from TCG.](http://www.trustedcomputinggroup.org/community/2012/11/trusted_computing_group_certifies_three_ifmap_servers_for_security_automation_correlation_of_metadata)