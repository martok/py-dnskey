from typing import List, Dict, Optional, Union

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


class PublishedKeyCollection:
    def __init__(self, resolver: BaseResolver) -> None:
        self.explicit_nameservers: Optional[List[str]] = None
        self.resolver = resolver
        self.known_zones = set()
        self.zone_ds: Dict[str, Dict[str, ListOrError]] = dict()
        self.zone_dnskey: Dict[str, Dict[str, ListOrError]] = dict()
        self.zone_signers: Dict[str, Dict[str, ListOrError]] = dict()

    def set_explicit_nameservers(self, servers: List[str]):
        self.explicit_nameservers = servers

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
        self.zone_ds.setdefault(zone, dict())
        self.zone_dnskey.setdefault(zone, dict())
        self.zone_signers.setdefault(zone, dict())

        # If the user requested multiple resolvers, query each individually
        expl_roots = self.resolver.explicit_resolvers()
        if expl_roots is not None:
            for pubres in expl_roots:
                try:
                    answer = self.resolver.query_at(zone, "DS", pubres)
                    self.zone_ds[zone][answer.nameserver] = sorted(set(self._store_ds(ds) for ds in answer))
                except dns.resolver.NoAnswer as na:
                    # no DS keys published
                    self.zone_ds[zone][pubres] = []
                except dns.exception.DNSException as e:
                    self.zone_ds[zone][pubres] = e
        else:
            # Otherwise, let resolver handle it
            try:
                answer = self.resolver.query(zone, "DS")
                self.zone_ds[zone][answer.nameserver] = sorted(set(self._store_ds(ds) for ds in answer))
            except dns.resolver.NoAnswer as na:
                # no DS keys published
                self.zone_ds[zone][na.nameserver] = []
            except dns.exception.DNSException as e:
                self.zone_ds[zone]["ERR"] = e

        try:
            query_servers = self._get_ns_list(zone)
        except dns.exception.DNSException as e:
            query_servers = []
        for ns in query_servers:
            nsip = self.resolver.resolve_host(ns)
            try:
                answer = self.resolver.query_at(zone, "DNSKEY", nsip)
                self.zone_dnskey[zone][ns] = sorted(set(self._store_dnskey(dnskey) for dnskey in answer))
            except dns.resolver.NoAnswer as na:
                self.zone_dnskey[zone][ns] = []
            except dns.exception.DNSException as e:
                self.zone_dnskey[zone][ns] = e
            try:
                answer = self.resolver.query_at(zone, "RRSIG", nsip)
                self.zone_signers[zone][ns] = sorted(set(self._store_rrsig(sig) for sig in answer))
            except dns.resolver.NoAnswer as na:
                self.zone_dnskey[zone][ns] = []
            except dns.exception.DNSException as e:
                self.zone_signers[zone][ns] = e
        self.known_zones.add(zone)

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
        dsns = sorted(set(ns for zn in self.zone_ds.values() for ns in zn.keys()))
        zonens = sorted(set(ns for zn in self.zone_dnskey.values() for ns in zn.keys()))
        return list(dsns) + list(zonens)


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
