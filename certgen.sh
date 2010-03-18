#!/bin/bash

openssl req -x509 -new -newkey rsa:1024 -keyout server.key -out server.pem -nodes -subj /C=US/O=NixnuxMedia/OU=OpenSource/CN=$1/emailAddress=mattes@nixnux.org

openssl x509 -in server.pem -subject -noout
