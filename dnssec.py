import datetime
import subprocess
import sys
from pathlib import Path


def date_part(colon_line: str) -> datetime:
    words = colon_line.split()
    dt = words[2]
    if len(dt) != len("yyyymmddhhmmss"):
        raise ValueError(f"Unexpected date format: '{colon_line}'")
    return datetime.datetime.strptime(dt, "%Y%m%d%H%M%S")


class KeyFile:

    def __init__(self, path: Path):
        self.path_rr = path
        self.path_pk = path.with_suffix(".private")
        self.name = path.stem
        self.owner = path.owner()
        self.group = path.group()
        self.perm = path.stat().st_mode
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
                if "Created:" in line:
                    self.d_create = date_part(line)
                elif "Publish:" in line:
                    self.d_publish = date_part(line)
                elif "Activate:" in line:
                    self.d_active = date_part(line)
                elif "Inactive:" in line:
                    self.d_inactive = date_part(line)
                elif "Delete:" in line:
                    self.d_delete = date_part(line)
                elif "This is a " in line and "keyid" in line and "for" in line:
                    words = line.split()
                    if words[4] == "zone-signing":
                        self.type = "ZSK"
                    elif words[4] == "key-signing":
                        self.type = "KSK"
                    else:
                        raise ValueError(f"Unexpected key type word: '{words[4]}'")
                    if self.keyid != int(words[7][:-1]):
                        raise ValueError(f"{self.name} claims to be for id {self.keyid}, but is not!")
                    if self.zone != words[-1]:
                        raise ValueError(f"{self.name} claims to be for id {self.zone}, but is not!")

    def sort_key(self):
        return f"{self.zone}+{self.type}+{self.algo:3d}+{self.keyid:5d}"

    def state(self, ref=None):
        if ref is None:
            ref = datetime.datetime.now()
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
            ref = datetime.datetime.now()
        # check if the ordering is consistent, but ignore Created
        assigned = list(filter(lambda x: x is not None,
                               [self.d_publish, self.d_active, self.d_inactive, self.d_delete]))
        expected_order = list(sorted(assigned))
        if expected_order == assigned:
            return next(filter(lambda x: x > ref, assigned), None)
        return "Inconsistent Dates"

    def dnskey_rr(self):
        ret = []
        with self.path_rr.open("rt") as key:
            for line in key.readlines():
                if not line.startswith(";") and "DNSKEY" in line:
                    ret.append(line.split("DNSKEY")[1].strip())
        return "\n".join(ret).strip()


class DnsSec:

    def __init__(self, path: Path):
        self.path = path
        self.echo = True

    def _call(self, args):
        if self.echo:
            print("Executing: {str(args)}", file=sys.stderr)
        ret = subprocess.run(args, cwd=self.path)
        if ret.returncode != 0:
            raise OSError(f"Error executing process: {ret.returncode}\n{ret.stderr}")

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
