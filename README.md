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
        --when DATETIME       When computing states, use DATETIME instead of current
        -s, --state {PUB,ACT,INAC,DEL,FUT}
                              Filter keys by current state
        -t, --type {ZSK,KSK}
                              Filter keys by type
        -o, --sort {ZONE,ALG,ID,STATE,DATE}
                              Sort keys by attribute
        --print-record        Output DNSKEY RR payload in table


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

### Date/Time Input

For relative time, the following syntaxes are accepted:

| Syntax | Description | Example |
|--------|-------------|---------|
| #      | seconds     | 42      |
| #s     | Minutes     | 60m     |
| #h     | Hours       | 24h     |
| #d     | Days        | 7d      |
| #w     | Weeks       | 4w      |


For absolute points in time, the following syntaxes are accepted:

| Syntax                                                     | Description                               | Example        |
|------------------------------------------------------------|-------------------------------------------|----------------|
| YYYYMMDDHHmmss                                             | DNS timestamp format                      | 20230523104200 |
| #                                                          | Unix timestamp, seconds                   | 1677331582     |
| YYYY-MM-DD[*HH[:MM[:SS[.fff[fff]]]][+HH:MM[:SS[.ffffff]]]] | ISO 8601, as processed by [Python][pyiso] | 2022-07-29     |
| +FMT                                                       | Relative time to now, as described above  | +8w            |

[pyiso]: https://docs.python.org/3/library/datetime.html#datetime.datetime.fromisoformat

