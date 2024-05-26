# dnsnatproxy

The implementation of name-based routing.

The custom DNS server allocates IPs in its private network (behind VPN) for some names and setup NAT to make them available by the client by this ip. It is coupled with Wireguard VPN to be able to route these IPs.


## Installing

```bash
apt install python3-pip wireguard

git clone ...
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

echo ams > ../paths.txt
echo brit >> ../paths.txt

# create some route table
echo 'intel.com 1' > ../routes.txt

cp dnsnatproxy.service /etc/systemd/system/
systemctl start dnsnatproxy
systemctl enable dnsnatproxy
```
