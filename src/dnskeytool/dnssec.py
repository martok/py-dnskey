import shutil
import subprocess
import sys
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Optional

import dns.rdata

from .dtutil import parse_dnsdatetime, fmt_dnsdatetime, nowutc


class KeyFile:

    def __init__(self, path: Path):
        self.path_rr = path
        self.path_pk = path.with_suffix(".private")
        self.path_state = path.with_suffix(".state")
        self.name = path.stem
        ff = path.stem.split("+")
        self.zone = ff[0][1:]
        self.algo = int(ff[1])
        self.keyid = int(ff[2])
        self.type = ""
        self.d_create = None
        self.d_publish = None
        self.d_active = None
        self.d_inactive = None
        self.d_delete = None
        with path.open("rt") as key:
            for line in key.readlines():
                if not line.startswith(";"):
                    continue
                words = line.strip(";\n ").split(" ")
                match words:
                    case ["Created:", dt, *_]:
                        self.d_create = parse_dnsdatetime(dt)
                    case ["Publish:", dt, *_]:
                        self.d_publish = parse_dnsdatetime(dt)
                    case["Activate:", dt, *_]:
                        self.d_active = parse_dnsdatetime(dt)
                    case ["Inactive:", dt, *_]:
                        self.d_inactive = parse_dnsdatetime(dt)
                    case ["Delete:", dt, *_]:
                        self.d_delete = parse_dnsdatetime(dt)
                    case ["This", "is", "a", kind, "key,", "keyid", keyid, "for", zone]:
                        match kind:
                            case "zone-signing":
                                self.type = "ZSK"
                            case "key-signing":
                                self.type = "KSK"
                            case _:
                                raise ValueError(f"Unexpected key type word: '{words[4]}'")
                        if self.keyid != int(keyid[:-1]):
                            raise ValueError(f"{self.name} claims to be for id {self.keyid}, but is not!")
                        if self.zone != zone:
                            raise ValueError(f"{self.name} claims to be for id {self.zone}, but is not!")

    def __repr__(self):
        return f"KeyFile({str(self)})"

    def __str__(self):
        return f"{self.zone}+{self.algo:03d}+{self.keyid:05d}"

    def sort_key(self):
        return f"{self.zone}+{self.type}+{self.algo:03d}+{self.keyid:05d}"

    def signer_id(self):
        return f"{self.algo:03d}+{self.keyid:05d}"

    def state(self, ref=None):
        if ref is None:
            ref = nowutc()
        if self.d_delete is not None and self.d_delete <= ref:
            return "DEL"
        if self.d_inactive is not None and self.d_inactive <= ref:
            return "INAC"
        if self.d_active is not None and self.d_active <= ref:
            return "ACT"
        if self.d_publish is not None and self.d_publish <= ref:
            return "PUB"
        if self.d_create is not None and self.d_create > ref:
            return "FUT"
        return ""

    def next_change(self, ref=None):
        if ref is None:
            ref = nowutc()
        # check if the ordering is consistent, but ignore Created
        assigned = list(filter(lambda x: x is not None,
                               [self.d_publish, self.d_active, self.d_inactive, self.d_delete]))
        expected_order = list(sorted(assigned))
        if expected_order == assigned:
            return next(filter(lambda x: x > ref, assigned), None)
        raise ValueError("Inconsistent Dates")

    @staticmethod
    def _wrap_rr(text: str, initial_indent: str=""):
        return textwrap.wrap(text, width=128, initial_indent=initial_indent, subsequent_indent=initial_indent + "    ", break_long_words=False)

    def dnskey_rr(self, *, indent=""):
        ret = []
        with self.path_rr.open("rt") as key:
            for line in key.readlines():
                if not line.startswith(";") and "DNSKEY" in line:
                    key = line.split("DNSKEY")[1].strip()
                    key = self._wrap_rr(key, indent)
                    ret.extend(key)
        return "\n".join(ret)

    def ds_rr(self, *, indent=""):
        # Try native first
        rr = self.dnskey_rr()
        try:
            abs_zone = dns.name.from_text(self.zone)
            dnskey = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, rr.replace("\n", " "))
            ds = dns.dnssec.make_ds(abs_zone, dnskey, dns.dnssec.DSDigest.SHA256)
            return "\n".join(self._wrap_rr("DS " + ds.to_text().upper(), indent))
        except dns.exception.DNSException:
            return ""

    def is_supported(self) -> Optional[bool]:
        from .data.supported_keys import SUPPORTED_ALG_TLD
        labels = self.zone.split(".")
        for last in reversed(range(1, len(labels))):
            check = ".".join(labels[-last-1:-1])
            supp = SUPPORTED_ALG_TLD.get(check, None)
            if supp is not None:
                return self.algo in supp
        return None

    def set_perms(self, *,
                  rr_perm: int = 0o644, rr_owner: str = "root", rr_grp: str = "bind",
                  pk_perm: int = 0o600, pk_owner: str = "bind", pk_grp: str = "bind",
                  check_only: bool = False) -> bool:

        def adjust(file: Path, perm, user, grp):
            change_made = False
            if file.owner() != user or file.group() != grp:
                if not check_only:
                    shutil.chown(file, user=user, group=grp)
                change_made = True
            if file.stat().st_mode & 0o777 != perm:
                if not check_only:
                    file.chmod(perm)
                change_made = True
            return change_made

        res = False
        res = adjust(self.path_rr, rr_perm, rr_owner, rr_grp) or res
        res = adjust(self.path_pk, pk_perm, pk_owner, pk_grp) or res
        return res


class DnsSec:

    def __init__(self, path: Path):
        self.path = path
        self.echo = True

    def _call(self, args):
        if self.echo:
            print(f"Executing: {str(args)}", file=sys.stderr)
        ret = subprocess.run(args, cwd=self.path, stdout=subprocess.PIPE, text=True)
        if ret.returncode != 0:
            raise OSError(f"Error executing process: {ret.returncode}\n{ret.stderr}")
        return ret.stdout.strip().splitlines(keepends=False)

    def _iter_keyfiles(self, zone: str):
        files = self.path.glob(f"K{zone}+*+*.key")
        for file in files:
            if not file.with_suffix(".private").exists():
                print(f"Warning: {file.name} exists, but corresponding .private does not!", file=sys.stderr)
                continue
            yield file

    def list_keys(self, zone: str, recursive=False):
        result = []
        if recursive:
            zone = "*." + zone.lstrip(".")
        for pk in self._iter_keyfiles(zone):
            kf = KeyFile(pk)
            result.append(kf)
        return list(sorted(result, key=KeyFile.sort_key))

    def key_settime(self, key: KeyFile, *,
                    publish: Optional[datetime] = None, activate: Optional[datetime] = None,
                    inactivate: Optional[datetime] = None, delete: Optional[datetime] = None):
        p = []
        if publish is not None:
            p += ["-P", fmt_dnsdatetime(publish)]
        if activate is not None:
            p += ["-A", fmt_dnsdatetime(activate)]
        if inactivate is not None:
            p += ["-I", fmt_dnsdatetime(inactivate)]
        if delete is not None:
            p += ["-D", fmt_dnsdatetime(delete)]
        if p:
            self._call(["dnssec-settime", *p, key.name])

    def key_gentemplate(self, template: KeyFile,
                        publish: Optional[datetime] = None, activate: Optional[datetime] = None,
                        inactivate: Optional[datetime] = None, delete: Optional[datetime] = None) -> KeyFile:
        # dnssec-keygen can only do successor *or* custom times, so create first and then adjust
        pipe = self._call(["dnssec-keygen", "-S", template.name, "-i", "0"])
        new_file = pipe[-1] + ".key"
        new_key = KeyFile(self.path / new_file)
        self.key_settime(new_key, publish=publish, activate=activate, inactivate=inactivate, delete=delete)
        return new_key


