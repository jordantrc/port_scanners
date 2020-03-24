#!/bin/bash

if [ "$#" -le 1 ]; then
    echo "Usage: pipa-route.sh <add|delete> [gateway]"
    exit 1
fi

ACTION=$1
GATEWAY=$2
SYSTEM=`uname -s`

echo "determined system type is $SYSTEM"

if [ "$ACTION" = "add" ]; then
    echo "adding routes for private IP address space through gateway $GATEWAY"
    
    # routes for macOS
    if [ "$SYSTEM" = "Darwin" ]; then
        route add -net 10.0.0.0/8 $GATEWAY
        route add -net 172.16.0.0/12 $GATEWAY
        route add -net 192.168.0.0/16 $GATEWAY
    fi

    # routes for Linux
    if [ "$SYSTEM" = "Linux" ]; then
        route add -net 10.0.0.0 netmask 255.0.0.0 gw $GATEWAY
        route add -net 172.16.0.0 netmask 255.240.0.0 gw $GATEWAY
        route add -net 192.168.0.0 netmask 255.255.0.0 gw $GATEWAY
    fi
fi

if [ "$ACTION" = "delete" ]; then
    echo "deleting routes for private IP address spaces"

    # routes for macOS
    if [ "$SYSTEM" = "Darwin" ]; then
        GATEWAY=$(netstat -rn | grep -E '^10\s+' | awk '{print $2}')
        route delete -net 10.0.0.0/8 $GATEWAY
        route delete -net 172.16.0.0/12 $GATEWAY
        route delete -net 192.168.0.0/16 $GATEWAY
    fi

    # routes for Linux
    if [ "$SYSTEM" = "Linux" ]; then
        GATEWAY=$(route -n | grep '10.0.0.0' | awk '{print $2}')
        route delete -net 10.0.0.0 netmask 255.0.0.0 gw $GATEWAY
        route delete -net 172.16.0.0 netmask 255.240.0.0 gw $GATEWAY
        route delete -net 192.168.0.0 netmask 255.255.0.0 gw $GATEWAY
    fi
fi
