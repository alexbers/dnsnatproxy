#!/bin/bash

# generates bay_srv.conf and client configs
if [ -d configs ]; then
    echo "./configs dir already exists, remove it and restart"
    exit 1
fi

mkdir -p configs

if ! cd configs; then
    echo "failed to change dir to configs"
    exit 1
fi

# detect external ip
IP=`curl -s https://ipinfo.io/ip`
if [[ ! $IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "No external IP detected, exiting"
  exit 1
fi

NET="10.163.0"
PORT=5300

SRV_PRIV_KEY=`wg genkey`
SRV_PUB_KEY=`echo "$SRV_PRIV_KEY"|wg pubkey`

# write initial config
echo "[Interface]
Address = 10.163.0.1/24
PrivateKey = $SRV_PRIV_KEY
ListenPort = $PORT
PostUp = iptables -t nat -A POSTROUTING -s ${NET}.0/24 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s ${NET}.0/24 -j MASQUERADE
PostUp = sysctl net.ipv4.ip_forward=1
" > bay_srv.conf

for i in {2..255}; do
  CLT_PRIV_KEY=`wg genkey`
  CLT_PUB_KEY=`echo "$CLT_PRIV_KEY"|wg pubkey`

  echo "[Peer]
PublicKey = $CLT_PUB_KEY
AllowedIPs = ${NET}.${i}/32
" >> bay_srv.conf

  echo "[Interface]
PrivateKey = $CLT_PRIV_KEY
Address = ${NET}.${i}/24
DNS = ${NET}.1

[Peer]
PublicKey = $SRV_PUB_KEY
Endpoint = $IP:$PORT
AllowedIPs = 10.163.0.0/24,8.8.8.8/32,100.64.0.0/12" > bay_clt_$i.conf

done

echo "Configs are generated, see ./configs dir"
