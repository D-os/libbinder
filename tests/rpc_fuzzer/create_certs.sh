#!/bin/sh

# As explained in
#  https://gist.github.com/darrenjs/4645f115d10aa4b5cebf57483ec82eca

openssl genrsa -des3 -passout pass:xxxx -out server.pass.key 2048
openssl rsa -passin pass:xxxx -in server.pass.key -out server.key
rm -f server.pass.key

openssl req \
    -subj "/" \
    -new -key server.key -out server.csr

openssl x509 -req -sha256 -days 99999 -in server.csr -signkey server.key -out server.crt
rm -f server.csr
