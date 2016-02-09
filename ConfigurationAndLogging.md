## Introduction ##

The following is the existing URI layout of omapd's configuration and logging HTTP API. It's based on RESTful concepts, although it isn't entirely RESTful.


### Configuration ###
  * `GET /config`
> return the current configuration (this could be a very large object, so be careful)
  * `GET /config/server`
> return the current server configuration (i.e. everything except client configurations)
  * `GET /config/server/port`
> return the tcp port number currently in use by omapd
  * `PUT /config/server/port`
> change the port number used by omapd. you will need to re-establish your connection
  * `GET /config/server/certificates`
> return a list of available certificates and their URIs
  * `GET /config/server/certificates/<name>`
> return the certificate with the given name
  * `PUT /config/server/certificates/<name>`
> replace the certificate with the given name with the one in the request payload
  * `GET /config/server/certificates/current`
> return the name of the certificate currently in use by omapd's SOAP endpoint
  * `PUT /config/server/certificates/current`
> replace the certificate currently in use with the one specified in the request payload


### Logging ###

  * `GET /logs`
> return a list of available logs and their URIs
  * `GET /logs/protocol`
> return a list of all protocol (i.e. xml/soap message) logs and their URIs, or if there is only one, return it
  * `GET /logs/protocol/request`, `/logs/protocol/response`, etc
> return sliced logs
  * `GET /logs/debug`, etc
> return other levels of logging information. need help here since i'm not familiar with what other omapd log info is useful

  * `GET /logs/...?tail=n`
> return the last n log messages

  * experimental feature: use websockets to present realtime logging through the browser (would only work in chrome and ff 3.7)