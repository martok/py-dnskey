# dnskeytool

Simple tool for DNSSEC key management.


## Usage

```
usage: dnskeytool [-h] [--dir DIR] COMMAND ...

options:
  -h, --help  show this help message and exit
  --dir DIR   directory containing key files

positional arguments:
  COMMAND
    list [-h] [-r] [-s {PUB,ACT,INAC,DEL,FUT}] ZONE
      List currently present keys and their timing

      positional arguments:
        ZONE                  DNS zone to work on

      options:
        -r, --recurse         Show key for all zones below the given one
        -s, --state {PUB,ACT,INAC,DEL,FUT}
                              Filter keys by current state
        -t, --type {ZSK,KSK}
                              Filter keys by type

    archive [-h] [-r] [-n] [--auto] ZONE TARGET
      Move expired keys to archive location

      positional arguments:
        ZONE           DNS zone to work on
        TARGET         Target path to move to

      options:
        -r, --recurse  Recursively act on zones below the given one
        -n, --dry-run  Don't perform action, just show plan
        --auto         Automatically append year of inactivation to TARGET

```
