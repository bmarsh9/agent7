#!/bin/bash
#usage: bash <filename.sh> (all,ca,server,client) <server hostname> <client hostname> <password>
#Ex. bash test.sh server 10.5.200.82 client # generates server certificate

cdir="/home/bmarshall/honeyad/agent/certauth/testing"
outdir="/home/bmarshall/honeyad/agent/agentbuild/windows"

function ca () {
    openssl genrsa -out ca.key 2048
    openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt
}

function server () {
    openssl genrsa -out server.key 2048
    openssl req -sha512 -new -key server.key -out server.csr -config $cdir/config/server.conf
    echo "C2E9862A0DA8E970" > serial
    openssl x509 -days 3650 -req -sha512 -in server.csr -CAserial serial -CA ca.crt -CAkey ca.key -out server.crt -extensions v3_req -extfile $cdir/config/server.conf
    mv server.key server.key.pem && openssl pkcs8 -in server.key.pem -topk8 -nocrypt -out server.key
}

function client () {
    openssl genrsa -out $outdir/client.key 2048
    openssl req -sha512 -new -key $outdir/client.key -out $cdir/client.csr -config $cdir/config/client.conf
    openssl x509 -days 3650 -req -sha512 -in $cdir/client.csr -CAserial $cdir/serial -CA $cdir/ca.crt -CAkey $cdir/ca.key -out $outdir/client.crt -extensions v3_req -extensions usr_cert  -extfile $cdir/config/client.conf
}

# ---------- Default Arguments -----------

#// Server hostname
if [ -z "$2" ]
then
    SERVER_HOSTNAME="10.5.200.82"
else
    SERVER_HOSTNAME="$2"
fi

#// Client hostname
if [ -z "$3" ]
then
    CLIENT_HOSTNAME="client"
else
    CLIENT_HOSTNAME="$3"
fi

#// Password
if [ -z "$4" ]
then
    PASSWORD="i837ip0vi349unldskhvl3liu4230994tojvdlwevjwevFGHEJRG"
else
    PASSWORD="$4"
fi

RANDOM_NUMBER=$((1 + RANDOM % 1000000))

# ---------- Create certificate ---------
if [ $1 = "all" ]
then
    ca $PASSWORD
    server $SERVER_HOSTNAME $PASSWORD
    client $CLIENT_HOSTNAME $PASSWORD

elif [ $1 = "ca" ]
then
    ca $PASSWORD

elif [ $1 = "server" ]
then
    server $SERVER_HOSTNAME $PASSWORD

elif [ $1 = "client" ]
then
    client $CLIENT_HOSTNAME $PASSWORD
else
    echo "invalid argument"
fi
