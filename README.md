# dnsnatproxy

The implementation of name-based routing.

It is implemented using custom DNS server inside WireGuard VPN. The network 100.64.0.0/12 is inside the vpn.

If a client asks for the name that not in name-based route table, the real IP is returned and the client don't uses VPN to reach that name.

If a client asks for the name that are in route table, the address from network 100.64.0.0/12 is returned to him and this address NAT'ed to the real name using some outgoing path. For example "ams" path can lead to Amsterdam, and "brit" path - to Britain. Every path is just a tunnel, a pair of WireGuard configs.

The client can modify its route table, for example if the server has "ams" path, if client resolves alexbers.com.ams, all requests on alexbers.com and all its subdomains will be routed to "ams" path. To see your routing table, visit http://vpn.vpn special address from the VPN. To remove route, add suffix ".default" to it. To modify default route, use name "default", for example "default.ams" will direct traffic to "ams" path by default.

## Installing

```bash
apt install python3-pip wireguard

cd /root
git clone https://github.com/alexbers/dnsnatproxy
cd dnsnatproxy
pip install -r requirements.txt --break-system-packages

cd setup

# generate local wireguard configs
./gen_in_wg_configs.sh
cp ./configs/bay_srv.conf /etc/wireguard/
systemctl start wg-quick@bay_srv
systemctl enable wg-quick@bay_srv

# generate configs for outgoing tunnels
./gen_out_wg_configs.sh 1 123.123.123.123
./gen_out_wg_configs.sh 2 200.100.50.25
...
cp out_clt1.conf /etc/wireguard/ams_clt.conf
cp out_clt2.conf /etc/wireguard/brit_clt.conf
systemctl start wg-quick@ams_clt wg-quick@brit_clt
systemctl enable wg-quick@ams_clt wg-quick@brit_clt

cd ..

# run the config on the remotes, check pings

# give name for your paths

echo ams > paths.txt
echo brit >> paths.txt

# create some route table
echo 'intel.com 1' > routes.txt

cp setup/dnsnatproxy.service /etc/systemd/system/
systemctl start dnsnatproxy
systemctl enable dnsnatproxy
```

## Automate Updating

```bash
cd /root/dnsnatproxy
cp setup/create_routes.py .

# modify create_routes.py to fit your needs

cp setup/dnsnatproxy-updater.service /etc/systemd/system/
systemctl start dnsnatproxy-updater
systemctl enable dnsnatproxy-updater
```
