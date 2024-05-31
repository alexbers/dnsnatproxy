import asyncio
import traceback
import collections
import random
import time
import os
import signal

import dnslib
import iptc
import aiodns
import aiofiles
from aiohttp import web

# We use ips 100.64.0.0 - 100.127.255.255

THIS_HOST_VPN_IP = "10.163.0.1"
DNS_CACHE_MIN_EXPIRATION = 5
DNS_CACHE_MAX_EXPIRATION = 10*60
DNS_CACHE_CAPACITY = 100_000


def iter_subdomains(domain):
    domain = domain.rstrip(".")
    parts = domain.split(".")
    for start_part in range(len(parts)):
        yield ".".join(parts[start_part:])


class FwdStrategyMgr:
    clt_to_name_to_strategy = collections.defaultdict(dict)
    out_paths = ["direct", "out"]

    async def record_new_strategy(clt_ip, name, strategy):
        name = name.replace(" ", "_")
        async with aiofiles.open('user_routes.txt', mode='a') as f:
            await f.write(f"{clt_ip} {name} {strategy}\n")

        FwdStrategyMgr.clt_to_name_to_strategy[clt_ip][name] = strategy
        if strategy == 0:
            del FwdStrategyMgr.clt_to_name_to_strategy[clt_ip][name]


    def load_outgoing_paths():
        FwdStrategyMgr.out_paths = ["direct"]
        try:
            with open('paths.txt', mode='r') as f:
                for line in map(str.strip, f):
                    if not line:
                        continue
                    FwdStrategyMgr.out_paths.append(line)
            print(f"Loaded {len(FwdStrategyMgr.out_paths)} paths:", ", ".join(FwdStrategyMgr.out_paths))
        except Exception as E:
            traceback.print_exc()


    def load_strategies():
        try:
            open('routes.txt', mode='a+').close()
            with open('routes.txt', mode='r') as f:
                FwdStrategyMgr.clt_to_name_to_strategy = collections.defaultdict(dict)
                for line in map(str.strip, f):
                    fields = line.split()
                    if len(fields) != 2:
                        print("Bad line in system routes", line)
                        continue

                    name, strategy = fields
                    try:
                        strategy = int(strategy)
                    except ValueError:
                        print("Bad strategy in system routes", line)
                        continue

                    FwdStrategyMgr.clt_to_name_to_strategy["all"][name] = strategy
                    if strategy == 0:
                        del FwdStrategyMgr.clt_to_name_to_strategy["all"][name]

            open('user_routes.txt', mode='a+').close()
            with open('user_routes.txt', mode='r') as f:
                for line in map(str.strip, f):
                    fields = line.split()
                    if len(fields) != 3:
                        print("Bad line in user routes", line)
                        continue

                    clt_ip, name, strategy = fields
                    try:
                        strategy = int(strategy)
                    except ValueError:
                        print("Bad line in user routes", line)
                        continue

                    FwdStrategyMgr.clt_to_name_to_strategy[clt_ip][name] = strategy
                    if strategy == 0:
                        del FwdStrategyMgr.clt_to_name_to_strategy[clt_ip][name]

            r = sum(len(v) for v in FwdStrategyMgr.clt_to_name_to_strategy.values())
            print(f"Loaded {r} routes")
        except Exception as E:
            traceback.print_exc()


    def get_list_by_client(clt_ip):
        ans = {}

        for k, v in FwdStrategyMgr.clt_to_name_to_strategy.get(clt_ip, {}).items():
            ans[k] = FwdStrategyMgr.out_paths[int(v)]
        return ans

    def get(clt_ip, name, real_ip):
        if not real_ip:
            return 0
        if real_ip == THIS_HOST_VPN_IP:
            return 0

        name_to_strategy = FwdStrategyMgr.clt_to_name_to_strategy.get(clt_ip, {})
        for subdomain in iter_subdomains(name):
            if subdomain in name_to_strategy:
                return name_to_strategy[subdomain]

        all_name_to_strategy = FwdStrategyMgr.clt_to_name_to_strategy.get("all", {})
        for subdomain in iter_subdomains(name):
            if subdomain in all_name_to_strategy:
                return all_name_to_strategy[subdomain]

        # last resort: try to resolve real ip as a name
        return all_name_to_strategy.get(real_ip, 0)


class NATMgr:
    COMMENT = "natproxy"
    adding_first_time = True

    @staticmethod
    def cleanup_old_rules():
        table = iptc.Table(iptc.Table.NAT)
        table.autocommit = False
        chain = iptc.Chain(table, "PREROUTING")
        for rule in chain.rules:
            for match in rule.matches:
                if match.name == "comment":
                    if match.parameters["comment"] == NATMgr.COMMENT:
                        chain.delete_rule(rule)
                        break
        table.commit()
        table.autocommit = True

    @staticmethod
    def add_nat_rule(client_ip, fake_ip, real_ip, name):
        print("add rule", client_ip, fake_ip, real_ip, name)
        r = iptc.Rule()
        r.set_src(client_ip)
        r.set_dst(fake_ip)
        r.create_target("DNAT")
        r.create_match("comment").comment = NATMgr.COMMENT
        r.create_match("comment").comment = name
        r.target.to_destination = real_ip

        c = iptc.Chain(iptc.Table(iptc.Table.NAT), 'PREROUTING')
        c.insert_rule(r)

        # there is some bug in kernel, where the very first rule doesn't add
        if NATMgr.adding_first_time:
            NATMgr.adding_first_time = False
            try:
                NATMgr.del_nat_rule(client_ip, fake_ip, real_ip, name)
            except iptc.ip4tc.IPTCError:
                pass
            c.insert_rule(r)


    @staticmethod
    def del_nat_rule(client_ip, fake_ip, real_ip, name):
        print("del rule", client_ip, fake_ip, real_ip, name)
        r = iptc.Rule()
        r.set_src(client_ip)
        r.set_dst(fake_ip)
        r.create_target("DNAT")
        r.create_match("comment").comment = NATMgr.COMMENT
        r.create_match("comment").comment = name
        r.target.to_destination = real_ip

        c = iptc.Chain(iptc.Table(iptc.Table.NAT), 'PREROUTING')
        c.delete_rule(r)


class IpAllocator:
    MAX_CAPACITY = 10000
    LEASE_EXPIRATION_SEC = 600
    ERROR_IP = "127.127.127.127"

    def __init__(self, client_ip):
        self.mapping = collections.OrderedDict()
        self.backmapping = {}
        self.client_ip = client_ip
        self.allocs = 0

    def allocate(self, name, real_ip, strategy):
        t = time.time()
        if not self.mapping:
            ip = self.allocate_next_ip(strategy)
            self.mapping[ip] = (t, name, real_ip)
            self.backmapping[name] = ip
            NATMgr.add_nat_rule(self.client_ip, ip, real_ip, name)
            return ip

        if name in self.backmapping:
            ip = self.backmapping[name]
            tt, oldname, oldrealip = self.mapping[ip]
            self.mapping[ip] = (t, name, real_ip)
            self.mapping.move_to_end(ip)
            if oldrealip != real_ip:
                NATMgr.del_nat_rule(self.client_ip, ip, oldrealip, oldname)
                NATMgr.add_nat_rule(self.client_ip, ip, real_ip, name)
            return ip

        oldip, (tt, oldname, oldrealip) = self.mapping.popitem(last=False)

        if t - tt > self.LEASE_EXPIRATION_SEC:
            del self.backmapping[oldname]
            del self.mapping[oldip]
            NATMgr.del_nat_rule(self.client_ip, oldip, oldrealip, oldname)
        else:
            # put back
            self.mapping[oldip] = (tt, oldname, oldrealip)
            self.mapping.move_to_end(oldip, last=False)

        if len(self.mapping) >= self.MAX_CAPACITY:
            return self.ERROR_IP

        ip = self.allocate_next_ip(strategy)
        self.mapping[ip] = (t, name, real_ip)
        self.mapping.move_to_end(ip)
        self.backmapping[name] = ip
        NATMgr.add_nat_rule(self.client_ip, ip, real_ip, name)
        return ip

    def deallocate(self, name):
        # if name not in self.backmapping:
            # return

        for oldname in list(self.backmapping):
            for subdomain in iter_subdomains(oldname):
                if subdomain == name:
                    oldip = self.backmapping[oldname]
                    tt, oldname, oldrealip = self.mapping[oldip]

                    NATMgr.del_nat_rule(self.client_ip, oldip, oldrealip, oldname)
                    del self.mapping[oldip]
                    del self.backmapping[oldname]
                    break


    # def get(self, ip):
    #     if ip not in self.mapping:
    #         return None
    #     t, name, realip = self.mapping[ip]
    #     if time.time() - t > self.LEASE_EXPIRATION_SEC:
    #         return None
    #     return name


    def allocate_next_ip(self, strategy):
        print("allocate_next_ip", strategy)
        if len(self.mapping) >= self.MAX_CAPACITY:
            return self.ERROR_IP

        for i in range(self.MAX_CAPACITY):
            self.allocs += 1
            if self.allocs > self.MAX_CAPACITY:
                self.allocs = 1

            START_IDX = 63
            ip = f"100.{START_IDX+strategy}.{self.allocs//256}.{self.allocs%256}"

            if ip not in self.mapping:
                return ip
        return self.ERROR_IP


class MulticlientIpAllocator:
    def __init__(self):
        self.clt_to_allocator = {}

    def allocate(self, client_ip, name, real_ip, strategy):
        if client_ip not in self.clt_to_allocator:
            self.clt_to_allocator[client_ip] = IpAllocator(client_ip)
        return self.clt_to_allocator[client_ip].allocate(name, real_ip, strategy)


    def deallocate(self, client_ip, name):
        if client_ip not in self.clt_to_allocator:
            return
        return self.clt_to_allocator[client_ip].deallocate(name)


    def get(self, client_ip, ip):
        if client_ip not in self.clt_to_allocator:
            return None
        return self.clt_to_allocator[client_ip].get(ip)


    def get_clt(self, client_ip):
        if client_ip not in self.clt_to_allocator:
            return collections.OrderedDict()
        return self.clt_to_allocator.get(client_ip).mapping


clt_ip_allocation = MulticlientIpAllocator()


class ExpirableCache:
    def __init__(self, min_ttl, max_ttl, capacity):
        self.mapping = collections.OrderedDict()
        self.max_ttl = max_ttl
        self.min_ttl = min_ttl
        self.capacity = capacity

    def get(self, name):
        if name not in self.mapping:
            return None

        t_exp, ip = self.mapping[name]
        return ip

    def put(self, name, ip, ttl=0):
        ttl = max(ttl, self.min_ttl)
        ttl = min(ttl, self.max_ttl)

        t_exp = time.time() + ttl

        self.mapping[name] = (t_exp, ip)
        self.mapping.move_to_end(name)

        if len(self.mapping) > self.capacity:
            self.mapping.popitem(last=False)


    def ttl_left(self, name):
        if name not in self.mapping:
            return 0

        t_exp, ip = self.mapping[name]
        return max(0, t_exp - time.time())


dnscache = ExpirableCache(min_ttl=DNS_CACHE_MIN_EXPIRATION,
                          max_ttl=DNS_CACHE_MAX_EXPIRATION, capacity=DNS_CACHE_CAPACITY)


class DNSServerProtocol:
    def __init__(self):
        self.resolver = aiodns.DNSResolver()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        dns_req = dnslib.DNSRecord.parse(data)
        asyncio.ensure_future(self.send_ans(addr, dns_req))


    async def send_ans(self, addr, dns_req):
        global dnscache
        global name_to_strategy
        global clt_ip_allocation

        qtype = dnslib.QTYPE[dns_req.questions[0].qtype]
        qname = dns_req.questions[0].qname.idna()
        simple_qname = qname.rstrip(".")

        clt_ip = addr[0]

        last_component = simple_qname.rsplit(".", 1)[-1]
        if last_component in FwdStrategyMgr.out_paths:
            out_idx = FwdStrategyMgr.out_paths.index(last_component)
            first_components = simple_qname.removesuffix(last_component).rstrip(".")
            clt_ip_allocation.deallocate(clt_ip, first_components)
            await FwdStrategyMgr.record_new_strategy(clt_ip, first_components, out_idx)
            simple_qname = "vpn.vpn"

        ans = dnslib.DNSRecord(
                dnslib.DNSHeader(id=dns_req.header.id, qr=1,aa=1,ra=1), q=dns_req.questions[0])

        ip = None
        resolved_ip = None
        if qtype == "A":
            cache_ttl_left = int(dnscache.ttl_left(simple_qname))
            if cache_ttl_left > 0:
                resolved_ip = dnscache.get(simple_qname)
                print(f"using cached {simple_qname}->{resolved_ip}, left {cache_ttl_left}")
            elif simple_qname == "vpn.vpn":
                resolved_ip = THIS_HOST_VPN_IP
            else:
                try:
                    resp = await self.resolver.query(qname.encode("idna"), 'A')
                    rand_resp = random.choice(resp)
                    resolved_ip = rand_resp.host
                    print(f"resolved {simple_qname}->{resolved_ip} ttl {rand_resp.ttl}")

                    dnscache.put(simple_qname, resolved_ip, ttl=rand_resp.ttl)
                except aiodns.error.DNSError as E:
                    print(E)
                    resolved_ip = dnscache.get(simple_qname)
                    if resolved_ip:
                        print(f"returning expired cached {simple_qname}->{resolved_ip}")

            ip = resolved_ip

            strategy = FwdStrategyMgr.get(clt_ip, simple_qname, ip)
            if strategy != 0:
                ip = clt_ip_allocation.allocate(clt_ip, simple_qname, resolved_ip, strategy)
                print(f"faking {simple_qname}->{ip} strategy {strategy}")

            if ip:
                ans.add_answer(dnslib.RR(qname,rdata=dnslib.A(ip), ttl=cache_ttl_left))

        print("resp", addr, len(dns_req.questions), qtype, qname, "ans", ip)
        self.transport.sendto(ans.pack(), addr)


async def webhandler(request):
    host = request.headers["host"]
    ip = request.remote

    ans = "Here is your routing table:\n"
    for k, v in reversed(FwdStrategyMgr.get_list_by_client(ip).items()):
        ans += f"{k:<60} {v}\n"

    ans += "\n\nAvailable destinations: " + ", ".join(FwdStrategyMgr.out_paths)
    ans += "\n\nMappings for debug:\n"

    mappings = list(clt_ip_allocation.get_clt(ip).items())

    mappings.sort(key=lambda k: k[1][0], reverse=True)

    for ip, (tt, name, real_ip) in mappings:
        ans += f"{ip:<20} {time.time() - tt:.0f} {name:<60}\n"

    return web.Response(status="200", body=ans)


def reload_routes():
    try:
        FwdStrategyMgr.load_outgoing_paths()
        FwdStrategyMgr.load_strategies()
    except Exception as E:
        traceback.print_exc()


def print_debug():
    
    try:
        for clt in clt_ip_allocation.clt_to_allocator:
            allocator = clt_ip_allocation.clt_to_allocator[clt]
            
            print("clt", clt, "mapping", allocator.mapping)
            print("clt", clt, "backmapping", allocator.backmapping)
            
    except Exception as E:
        traceback.print_exc()
    

def setup_signals():
        signal.signal(signal.SIGHUP, lambda signum, frame: reload_routes())
        signal.signal(signal.SIGUSR1, lambda signum, frame: print_debug())


async def main():
    NATMgr.cleanup_old_rules()
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DNSServerProtocol(), local_addr=(THIS_HOST_VPN_IP, 53))

    server = web.Server(webhandler)
    runner = web.ServerRunner(server)
    await runner.setup()
    site = web.TCPSite(runner, THIS_HOST_VPN_IP, 80)
    await site.start()

    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    reload_routes()
    setup_signals()
    asyncio.run(main())
