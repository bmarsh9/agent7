#!/bin/bash
#usage: bash <filename.sh> (all,ca,server,client) <server hostname> <client hostname> <password>
#Ex. bash test.sh server 10.5.200.82 client # generates server certificate

cdir="certauth"
zipdir="agentbuild/windows"
serverdir="certauth/server"
CADIR="certauth/ca"

function ca () {
    openssl genrsa -out $CADIR/ca.key 2048
    openssl req -x509 -new -nodes -key $CADIR/ca.key -sha256 -days 3650 -out $CADIR/ca.crt
}

function server () {
    openssl genrsa -out $serverdir/server.key 2048
    openssl req -sha512 -new -key $serverdir/server.key -out $serverdir/server.csr -config $cdir/config/server.conf
    echo "C2E9862A0DA8E970" > $cdir/serial
    openssl x509 -days 3650 -req -sha512 -in $serverdir/server.csr -CAserial $cdir/serial -CA $CADIR/ca.crt -CAkey $CADIR/ca.key -out $serverdir/server.crt -extensions v3_req -extfile $cdir/config/server.conf
    mv $serverdir/server.key $serverdir/server.key.pem && openssl pkcs8 -in $serverdir/server.key.pem -topk8 -nocrypt -out $serverdir/server.key
}

function client () {
    openssl genrsa -out $zipdir/client.key 2048
    openssl req -sha512 -new -key $zipdir/client.key -out $cdir/client.csr -config $cdir/config/client.conf
    openssl x509 -days 3650 -req -sha512 -in $cdir/client.csr -CAserial $cdir/serial -CA $cdir/ca.crt -CAkey $cdir/ca.key -out $zipdir/client.crt -extensions v3_req -extensions usr_cert  -extfile $cdir/config/client.conf
}

# ---------- Default Arguments -----------

#// Password
if [ -z "$2" ]
then
    PASSWORD="i837ip0vi349unldskhvl3liu4230994tojvdlwevjwevFGHEJRG"
else
    PASSWORD="$2"
fi

RANDOM_NUMBER=$((1 + RANDOM % 1000000))

# ---------- Create certificate ---------
if [ $1 = "all" ]
then
    ca $PASSWORD
    server $PASSWORD
    client $PASSWORD

elif [ $1 = "ca" ]
then
    ca $PASSWORD

elif [ $1 = "server" ]
then
    server $PASSWORD

elif [ $1 = "client" ]
then
    client $PASSWORD
else
    echo "invalid argument"
fi
