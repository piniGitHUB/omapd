/*
mapclient.cpp: Implementation of MapClient class

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

#include "mapclient.h"

MapClient::MapClient()
{
    _authType = MapRequest::AuthNone;
    _hasActiveSSRC = false;
    _hasActiveARC = false;
    _hasActivePoll = false;
}

MapClient::MapClient(QString authToken, MapRequest::AuthenticationType authType, QString pubId)
{
    _hasActiveSSRC = false;
    _hasActiveARC = false;
    _hasActivePoll = false;
    _authToken = authToken;
    _authType = authType;
    _pubId = pubId;
}
