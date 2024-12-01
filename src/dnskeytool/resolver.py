from typing import Optional, List, Iterable, Iterator

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
        if dns.inet.is_address(hostname):
            return hostname
        for af in self._af_order():
            try:
                answer = self.query(hostname, af)
                for a in answer:
                    return a.address
            except dns.resolver.LifetimeTimeout:
                pass
            except dns.resolver.NoAnswer:
                pass
        raise ValueError(f"Could not resolve any IP address of '{hostname}'")


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


class RecursiveResolver(BaseResolver):
    def __init__(self) -> None:
        super().__init__()
        self._query_cache = dict()

    def query(self, zone: str, what: str) -> Answer:
        key = (zone.upper(), what.upper())
        if key not in self._query_cache:
            nameservers = self._expand_root_servers()
            self._query_cache[key] = self._recursive_query(nameservers, zone, what)
        return self._query_cache[key]

    def query_at(self, zone: str, what: str, where: str) -> Answer:
        query = dns.message.make_query(zone, what)
        try:
            res = dns.query.tcp(query, where)
        except ConnectionError as ex:
            raise dns.resolver.NoNameservers(request=query, errors=[(where, 1, 53, ex, None)])

        return Answer(
            dns.name.from_text(zone),
            query.question[0].rdtype,
            query.question[0].rdclass,
            res,
            where,
            53,
        )

    def _expand_root_servers(self) -> Iterator[str]:
        from .data.dns import ROOT_SERVERS
        if self.prefer_v4:
            yield from (v4 for h, v4, v6 in ROOT_SERVERS)
            yield from (v6 for h, v4, v6 in ROOT_SERVERS)
        else:
            yield from (v6 for h, v4, v6 in ROOT_SERVERS)
            yield from (v4 for h, v4, v6 in ROOT_SERVERS)

    @staticmethod
    def _addr_from_additional(adds: List[dns.rrset.RRset]):
        result = dict()
        for add in adds:
            if add.name not in result:
                result[add.name] = dict()
            for k, v in add.items.items():
                if k.rdtype == dns.rdatatype.A or k.rdtype == dns.rdatatype.AAAA:
                    if k.rdtype in result[add.name]:
                        result[add.name][k.rdtype].append(k.address)
                    else:
                        result[add.name][k.rdtype] = [k.address]
        return result

    def _authority_ns_resolver(self, authority: List, additional: List) -> Iterator[str]:
        addrs = self._addr_from_additional(additional)

        # avoid excessive A/AAAA lookups by only generating them if actually needed
        def proto_gen(rdata: int, rr: str):
            for rrset in authority:
                if rrset.rdtype == dns.rdatatype.NS:
                    for nsrec in rrset:
                        nshost = nsrec.target
                        if nshost in addrs:
                            hints = addrs[nshost]
                            if rdata in hints:
                                yield from hints[rdata]
                        else:
                            answer = self.query(nshost.to_text(), rr)
                            for a in answer:
                                yield a.address

        if self.prefer_v4:
            yield from proto_gen(dns.rdatatype.A, "A")
            yield from proto_gen(dns.rdatatype.AAAA, "AAAA")
        else:
            yield from proto_gen(dns.rdatatype.AAAA, "AAAA")
            yield from proto_gen(dns.rdatatype.A, "A")

    @staticmethod
    def _make_NA(ans: Answer, ns: str):
        na = dns.resolver.NoAnswer(response=ans.response)
        na.nameserver = ns
        return na

    def _recursive_query(self, nameservers: Iterable[str], qname: str, what: str) -> Answer:
        errors = []
        for ns in nameservers:
            try:
                ans = self.query_at(qname, what, ns)
            except dns.resolver.NoNameservers:
                continue
            except dns.exception.DNSException:
                raise
            except ConnectionError as ex:
                errors.append((ns, 1, 53, ex, None))
                continue
            rcode = ans.response.rcode()
            if rcode == dns.rcode.NOERROR:
                # is this your final answer?
                if ans.rrset:
                    return ans

                # actually, try somewhere else
                for rrset in ans.response.answer:
                    if rrset.rdtype == dns.rdatatype.CNAME:
                        return self.query(rrset[0].target.to_text(), what)

                # response tells us a better authority?
                if ans.response.authority:
                    if any(rrset.rdtype == dns.rdatatype.SOA for rrset in ans.response.authority):
                        # we found the authority, but still got no answer
                        raise self._make_NA(ans, ns)
                    if not any(rrset.rdtype == dns.rdatatype.NS for rrset in ans.response.authority):
                        # reached the end of recursion without proper error
                        raise self._make_NA(ans, ns)
                    nameservers = self._authority_ns_resolver(ans.response.authority, ans.response.additional)
                    return self._recursive_query(nameservers, qname, what)
            elif rcode == dns.rcode.NXDOMAIN:
                raise dns.resolver.NXDOMAIN(qnames=[qname], responses={qname: ans.response})
            elif rcode == dns.rcode.YXDOMAIN:
                raise dns.resolver.YXDOMAIN()
        query = dns.message.make_query(qname, what)
        raise dns.resolver.NoNameservers(request=query, errors=errors)
