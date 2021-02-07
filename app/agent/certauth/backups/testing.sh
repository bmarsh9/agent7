#!/bin/bash

# Note: Make sure /etc/ssl/openssl.cnf exists and has a [ SAN ] line added

SERVER_HOSTNAME=10.5.200.82
CLIENT_HOSTNAME=10.5.100.2
PASSWORD=13916219
RANDOM_NUMBER=$((1 + RANDOM % 1000000))

# Create the CA Key and Certificate for signing Client Certs
#openssl genrsa -des3 -passout pass:$PASSWORD -out ca.key 4096
#openssl req -new -x509 -days 365 -passin pass:$PASSWORD -key ca.key -out ca.crt

# Create the Server Key, CSR, and Certificate
openssl genrsa -des3 -out server.key -passout pass:$PASSWORD 2048
openssl req -new -key server.key -subj "/C=US/ST=VA/O=honeyad" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=IP:$SERVER_HOSTNAME")) -passin pass:$PASSWORD -out server.csr

# Sign Server Certificate
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -passin pass:$PASSWORD -out server.crt

# Create the Client Key and CSR
openssl genrsa -des3 -out client.key -passout pass:$PASSWORD 2048
openssl req -new -key client.key -subj "/C=US/ST=VA/O=honeyad" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=IP:$CLIENT_HOSTNAME")) -passin pass:$PASSWORD -out client.csr

# Sign Client Certificate
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 02 -passin pass:$PASSWORD -out client.crt


