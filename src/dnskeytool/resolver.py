from typing import Union, Optional, List

import dns
from dns.resolver import Answer


def find_rrsets(query: dns.rrset.RRset, section: List[dns.rrset.RRset]) -> List[dns.rrset.RRset]:
    matching = []
    for rrset in section:
        if rrset.name == query.name and rrset.rdclass == query.rdclass and rrset.rdtype == query.rdtype:
            matching.extend(rrset)
    return matching


class BaseResolver:

    def __init__(self) -> None:
        super().__init__()
        self.prefer_v4 = False

    def _af_order(self):
        if self.prefer_v4:
            return ["A", "AAAA"]
        else:
            return ["AAAA", "A"]

    def explicit_resolvers(self) -> Optional[List[str]]:
        return None

    def query(self, zone: str, what: str) -> Answer:
        pass

    def query_at(self, zone: str, what: str, where: str) -> Answer:
        pass

    def resolve_host(self, hostname: str) -> str:
        pass


class StubResolver(BaseResolver):

    def __init__(self, query_servers: List[str]) -> None:
        super().__init__()
        self.servers = query_servers

    def explicit_resolvers(self) -> Optional[List[str]]:
        return self.servers

    def _query(self, zone: str, what: str, res: dns.resolver.Resolver) -> Answer:
        try:
            answer = res.resolve(zone, what, tcp=True)
            return answer
        except dns.resolver.NoAnswer as na:
            # special casing some common failures of Resolver:
            #   - RRSIG queries, which would not work since they are grouped by covers
            #   - NS queries at the nic, which are returned in the AUTHORITY section (not ANSWER)
            r: dns.message.Message = na.kwargs["response"]
            q = r.question[0]
            if q.rdtype == dns.rdatatype.RRSIG:
                return find_rrsets(q, r.answer)
            if q.rdtype == dns.rdatatype.NS:
                return find_rrsets(q, r.authority)
            # fake any nameserver response
            na.nameserver = res.nameservers[-1]
            raise na

    def query_at(self, zone: str, what: str, where: str) -> Answer:
        resolver = dns.resolver.Resolver()
        if where:
            resolver.nameservers = [where]
        elif self.servers:
            resolver.nameservers = self.servers
        return self._query(zone, what, resolver)

    def query(self, zone: str, what: str) -> Answer:
        resolver = dns.resolver.Resolver()
        if self.servers:
            resolver.nameservers = self.servers
        return self._query(zone, what, resolver)

    def resolve_host(self, hostname: str) -> str:
        if dns.inet.is_address(hostname):
            return hostname
        resolver = dns.resolver.Resolver()
        if self.servers:
            resolver.nameservers = self.servers
        for af in self._af_order():
            try:
                answer = resolver.resolve(hostname, af)
                for a in answer:
                    return a.address
            except dns.resolver.LifetimeTimeout:
                pass
            except dns.resolver.NoAnswer:
                pass
        raise ValueError(f"Could not resolve any IP address of '{hostname}' at {str(resolver.nameservers)}")
