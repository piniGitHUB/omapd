/*
mapclient.h: Declaration of MapClient Class

Copyright (C) 2011  Sarab D. Mattes <mattes@nixnux.org>

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

#ifndef MAPCLIENT_H
#define MAPCLIENT_H

#include "maprequest.h"
#include "subscription.h"

class MapClient
{
public:
    // Don't use, but needs to be here for QHash's methods
    // that return a default constructed value
    MapClient();

    MapClient(QString authToken, MapRequest::AuthenticationType authType, QString pubId);

    QString sessId() const { return _sessId; }
    QString pubId()  const { return _pubId; }
    QString authToken() const { return _authToken; }
    MapRequest::AuthenticationType authType() const { return _authType; }
    bool hasActiveSSRC() const { return _hasActiveSSRC; }
    bool hasActiveARC() const { return _hasActiveARC; }
    bool hasActivePoll() const { return _hasActivePoll; }
    QList<Subscription> subscriptionList() const { return _subscriptionList; }

    void setSessId(QString sessId) { _sessId = sessId; }
    void clearSessId() { _sessId = QString(); }
    void setPubId(QString pubId) { _pubId = pubId; }
    void setAuthToken(QString authToken) { _authToken = authToken; }
    void setAuthType(MapRequest::AuthenticationType authType) { _authType = authType; }
    void setHasActiveSSRC(bool hasActiveSSRC) { _hasActiveSSRC = hasActiveSSRC; }
    void setHasActiveARC(bool hasActiveARC) { _hasActiveARC = hasActiveARC; }
    void setHasActivePoll(bool hasActivePoll) { _hasActivePoll = hasActivePoll; }
    void setSubscriptionList(QList<Subscription> subList) { _subscriptionList = subList; }
    void emptySubscriptionList() { _subscriptionList.clear(); }

private:
    QString _sessId;
    QString _pubId;
    QString _authToken;
    MapRequest::AuthenticationType _authType;
    bool _hasActiveSSRC;
    bool _hasActiveARC;
    bool _hasActivePoll;
    QList<Subscription> _subscriptionList;
};

#endif // MAPCLIENT_H
