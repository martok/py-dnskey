from pprint import pprint
from typing import List, Dict, Optional, Union

import dns.dnssec
import dns.exception
import dns.inet
import dns.rdatatype
import dns.rdtypes.ANY.DNSKEY
import dns.rdtypes.ANY.DS
import dns.rdtypes.ANY.RRSIG
import dns.resolver

ListOrError = Union[dns.exception.DNSException, List[str]]


def find_rrsets(query: dns.rrset.RRset, section: List[dns.rrset.RRset]) -> List[dns.rrset.RRset]:
    matching = []
    for rrset in section:
        if rrset.name == query.name and rrset.rdclass == query.rdclass and rrset.rdtype == query.rdtype:
            matching.extend(rrset)
    return matching


class PublishedKeyCollection:
    def __init__(self) -> None:
        self.explicit_nameservers: Optional[List[str]] = None
        self.prefer_v4 = False
        self.resolver: Optional[str] = None
        self.used_resolver: Optional[str] = None
        self.known_zones = set()
        self.zone_ds: Dict[str, ListOrError] = dict()
        self.zone_dnskey: Dict[str, Dict[str, ListOrError]] = dict()
        self.zone_signers: Dict[str, Dict[str, ListOrError]] = dict()

    def set_explicit_nameservers(self, servers: List[str]):
        self.explicit_nameservers = servers

    def set_resolver(self, resolver: str):
        self.resolver = resolver

    def query_zone(self, zone: str):
        if zone in self.known_zones:
            return
        # on public resolver, fetch
        #   the DS that is currently being announced by the registrar
        #      (should be currently active KSKs)
        # on each zone server, fetch:
        #   the DNSKEYs currently published, and their RRSIGs
        #      (should be active + pre/postpublished ZSKs and KSKs, signed by active KSKs from DS)
        #   the DNSKEYs currently used in RRSIGs on other RRs
        #      (should be currently active ZSKs)
        try:
            answer = self._lookup(zone, "DS")
            self.used_resolver = answer.nameserver
            self.zone_ds[zone] = sorted(set(self._store_ds(ds) for ds in answer))
        except dns.exception.DNSException as e:
            self.zone_ds[zone] = e
        query_servers = self._get_ns_list(zone)
        self.zone_dnskey.setdefault(zone, dict())
        self.zone_signers.setdefault(zone, dict())
        for ns in query_servers:
            nsip = self._resolve(ns)
            try:
                answer = self._lookup(zone, "DNSKEY", nsip)
                self.zone_dnskey[zone][ns] = sorted(set(self._store_dnskey(dnskey) for dnskey in answer))
            except dns.exception.DNSException as e:
                self.zone_dnskey[zone][ns] = e
            try:
                answer = self._lookup(zone, "RRSIG", nsip)
                self.zone_signers[zone][ns] = sorted(set(self._store_rrsig(sig) for sig in answer))
            except dns.exception.DNSException as e:
                self.zone_signers[zone][ns] = e
        self.known_zones.add(zone)

    def _get_ns_list(self, zone: str):
        # user-defined server list
        if self.explicit_nameservers:
            return self.explicit_nameservers
        # query system-default resolver to find who is responsible, then query these
        answer = self._lookup(zone, "NS")
        return [rr.target.canonicalize().to_text() for rr in answer]

    def _lookup(self, zone: str, what: str, where: Optional[str] = None):
        resolver = dns.resolver.Resolver()
        if where is not None:
            resolver.nameservers = [where]
        elif self.resolver is not None:
            resolver.nameservers = [self.resolver]
        try:
            answer = resolver.resolve(zone, what, tcp=True)
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
            raise na

    def _resolve(self, name: str):
        if dns.inet.is_address(name):
            return name
        resolver = dns.resolver.Resolver()
        if self.resolver is not None:
            resolver.nameservers = [self.resolver]
        af_order = ["A", "AAAA"] if self.prefer_v4 else ["AAAA", "A"]
        for af in af_order:
            try:
                answer = resolver.resolve(name, af)
                for a in answer:
                    return a.address
            except dns.resolver.LifetimeTimeout:
                pass
            except dns.resolver.NoAnswer:
                pass
        raise ValueError(f"Could not resolve any IP address of '{name}' at {str(resolver.nameservers)}")

    @staticmethod
    def _store_ds(ds: dns.rdtypes.ANY.DS.DS):
        return f"{ds.algorithm:03d}+{ds.key_tag:05d}"

    @staticmethod
    def _store_dnskey(dnskey: dns.rdtypes.ANY.DNSKEY.DNSKEY):
        key_tag = dns.dnssec.key_id(dnskey)
        return f"{dnskey.algorithm:03d}+{key_tag:05d}"

    @staticmethod
    def _store_rrsig(sig: dns.rdtypes.ANY.RRSIG.RRSIG):
        return f"{sig.algorithm:03d}+{sig.key_tag:05d}"

    def contacted_servers(self):
        zonens = sorted(set(ns for zn in self.zone_dnskey.values() for ns in zn.keys()))
        zonens.insert(0, self.used_resolver)
        return zonens


def shorten_dns(name: str) -> str:
    if dns.inet.is_address(name):
        return name
    try:
        nam = dns.name.from_text(name).canonicalize()
        labels = [lab[:1] if i > 0 else lab for i, lab in enumerate(nam.labels)]
        snam = dns.name.Name(labels)
        return snam.to_text()
    except ValueError:
        return name
