#!/bin/bash

IDX=${1?"Usage: ./gen_configs.sh <index> <srv_ip>"}
IP=${2?"Usage: ./gen_configs.sh <index> <srv_ip>"}

if (( IDX < 1 )); then
  echo "IDX should be 1 or more"
  exit 1
fi

if [[ ! $IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Bad IP"
  exit 1
fi

BASE=63

BIDX=$(($BASE+$IDX))

NET="10.${BIDX}.0"
SRC_NET="100.${BIDX}.0"
PORT=$((5353+$IDX))

SRV_PRIV_KEY=`wg genkey`
SRV_PUB_KEY=`echo "$SRV_PRIV_KEY"|wg pubkey`

# write initial config
echo "[Interface]
PrivateKey = $SRV_PRIV_KEY
ListenPort = $PORT
Address=${NET}.1
PostUp = iptables -t nat -A POSTROUTING -s ${NET}.0/24 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s ${NET}.0/24 -j MASQUERADE
PostUp = sysctl net.ipv4.ip_forward=1
" > out_srv${IDX}.conf

CLT_PRIV_KEY=`wg genkey`
CLT_PUB_KEY=`echo "$CLT_PRIV_KEY"|wg pubkey`

echo "[Peer]
PublicKey = $CLT_PUB_KEY
AllowedIPs = ${NET}.2/32
" >> out_srv${IDX}.conf

echo "[Interface]
PrivateKey = $CLT_PRIV_KEY
Address = ${NET}.2/24
Table=${BIDX}
PostUp = iptables -t mangle -A PREROUTING -d ${SRC_NET}.0/16 -j MARK --set-mark ${BIDX}
PostUp = ip rule add fwmark ${BIDX} table ${BIDX}
PostUp = iptables -t nat -A POSTROUTING -s ${NET}.0/24 -j MASQUERADE
PostUp = sysctl net.ipv4.ip_forward=1
PostDown = iptables -t nat -D POSTROUTING -s ${NET}.0/24 -j MASQUERADE
PostDown = ip rule del fwmark ${BIDX} table ${BIDX}
PostDown = iptables -t mangle -D PREROUTING -d ${SRC_NET}.0/16 -j MARK --set-mark ${BIDX}

[Peer]
PublicKey = $SRV_PUB_KEY
Endpoint = $IP:$PORT
AllowedIPs = 0.0.0.0/0" > out_clt${IDX}.conf

echo "Configs are generated"
