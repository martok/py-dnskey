from typing import List, Dict, Optional, Union, Callable, Any

import dns.dnssec
import dns.exception
import dns.inet
import dns.rdatatype
import dns.rdtypes.ANY.DNSKEY
import dns.rdtypes.ANY.DS
import dns.rdtypes.ANY.RRSIG
import dns.resolver

from .resolver import BaseResolver, StubResolver

ListOrError = Union[dns.exception.DNSException, List[str]]
NameserverResponses = Dict[str, ListOrError]


class ZoneInfo:
    def __init__(self):
        super().__init__()
        self.ds: NameserverResponses = dict()
        self.dnskey: NameserverResponses = dict()
        self.rrsig: NameserverResponses = dict()

    def all_nameservers(self) -> set[str]:
        union = set()
        union.update(self.ds.keys(), self.dnskey.keys(), self.rrsig.keys())
        return union


class PublishedKeyCollection:
    def __init__(self, resolver: BaseResolver) -> None:
        self.explicit_nameservers: Optional[List[str]] = None
        self.resolver = resolver
        self.results: Dict[str, ZoneInfo] = dict()

    def set_explicit_nameservers(self, servers: List[str]):
        self.explicit_nameservers = servers

    def query_zone(self, zone: str):
        if zone in self.results:
            return
        # on public resolver, fetch
        #   the DS that is currently being announced by the registrar
        #      (should be currently active KSKs)
        # on each zone server, fetch:
        #   the DNSKEYs currently published, and their RRSIGs
        #      (should be active + pre/postpublished ZSKs and KSKs, signed by active KSKs from DS)
        #   the DNSKEYs currently used in RRSIGs on other RRs
        #      (should be currently active ZSKs)
        result = ZoneInfo()

        # If the user requested multiple resolvers, query each individually
        expl_roots = self.resolver.explicit_resolvers()
        if expl_roots is not None:
            for pubres in expl_roots:
                self._query_keys(result.ds, zone, pubres, "DS", self._store_ds)
        else:
            # Otherwise, let resolver handle it
            self._query_keys(result.ds, zone, None, "DS", self._store_ds)

        try:
            query_servers = self._get_ns_list(zone)
        except dns.exception.DNSException:
            query_servers = []

        for ns in query_servers:
            self._query_keys(result.dnskey, zone, ns, "DNSKEY", self._store_dnskey)
            self._query_keys(result.rrsig, zone, ns, "RRSIG", self._store_rrsig)
        self.results[zone] = result

    def _query_keys(self, result: NameserverResponses, zone: str, ns: Optional[str], what: str, rr2str: Callable[[Any], str]):
        try:
            if ns is None:
                answer = self.resolver.query(zone, what)
            else:
                nsip = self.resolver.resolve_host(ns)
                answer = self.resolver.query_at(zone, what, nsip)
            keyset = set(map(rr2str, answer))
            result[ns or answer.nameserver] = list(sorted(keyset))
        except dns.resolver.NoAnswer as na:
            result[ns or na.nameserver] = []
        except dns.exception.DNSException as e:
            result[ns or "ERR"] = e

    def _get_ns_list(self, zone: str):
        # user-defined server list
        if self.explicit_nameservers:
            return self.explicit_nameservers
        # query resolver to find who is responsible, then query these
        answer = self.resolver.query(zone, "NS")
        return [rr.target.canonicalize().to_text() for rr in answer]

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
        # servers we got DS records from go first
        dsns = set()
        allns = set()
        for zn in self.results.values():
            dsns.update(zn.ds.keys())
            allns.update(zn.all_nameservers())
        # sort by name first, then stable sort by ds-response (False sorts before True)
        result = list(allns)
        result.sort()
        result.sort(key=lambda ns: ns not in dsns)
        return result


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
