#!/bin/bash

# Trap SIGINT (CTRL-C) and exit gracefully
trap "echo 'Exiting...'; exit" SIGINT

# Loop and try until tun0 interface is up
until java -jar OscoreServerMar15.jar --msecret 0102030405060708090A0B0C0D0E0F10 --msalt 9e7ca92223786340 --sid 01 --rid 02 --kudos true --nonce-len 8 --debug true --listen-addr fd00::1 ; do
    echo "Waiting for tun0 interface to be available..."
    sleep 0.1
done