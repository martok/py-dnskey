# dnskeytool

Simple tool for DNSSEC key management.

## Installation

Install using pip:

```pip install --user .```

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
        -c, --calendar        Show relative time to each state change (default: only timestamp of next change)
        -p, --permissions     Print asterisk for keys with bad permissions


    archive [-h] [-r] [-n] [--auto] ZONE TARGET
      Move expired keys to archive location

      positional arguments:
        ZONE           DNS zone to work on
        TARGET         Target path to move to

      options:
        -r, --recurse  Recursively act on zones below the given one
        -n, --dry-run  Don't perform action, just show plan
        --auto         Automatically append year of inactivation to TARGET

    rotate [-h] -t {ZSK,KSK} [-n] [-b INTERVAL] [-l INTERVAL] [-o INTERVAL] [-a INTERVAL] ZONE
      Rotate keys based on lifetime

      positional arguments:
        ZONE                  DNS zone to work on

      options:
        -h, --help            show this help message and exit
        -t {ZSK,KSK}, --type {ZSK,KSK}
                              Filter keys by type
        -n, --dry-run         Don't perform action, just show plan
        -b INTERVAL, --prepublish INTERVAL
                              Time to publish keys before its activation date (Default: 1w)
        -l INTERVAL, --lifetime INTERVAL
                              Active lifetime of keys (Default: 2w)
        -o INTERVAL, --overlap INTERVAL
                              Overlap between active keys, calculated from the end of active phase (Default: 1w)
        -a INTERVAL, --postpublish INTERVAL
                              Time to publish keys after their deactivation date (Default: 1w)

    permissions [-h] [-n] FILES [FILES ...]
      Fix file permissions

      positional arguments:
        FILES          File or shell pattern to match, excluding file extension

      options:
        -h, --help     show this help message and exit
        -n, --dry-run  Don't perform action, just show files that would be changed

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

## Key Rotation

Automatic ZSK key rotation tries to achieve a gap-less key schedule by providing overlapping active keys.
In an example configuration, `--prepublish 7d --lifetime 14d --overlap 5d --postpublish 7d`:

```
Days ->                          (1)
Key                               |
0      ..AAAAAAAAAAAAIIIIIII--    V
1        PPPPPPPAAAAAAAAAAAAAAIIIIIII--
2                 PPPPPPPAAAAAAAAAAAAAAIIIIIII--
3                          PPPPPPPAAAAAAAAAAAAAAIIIIIII--
```

Keys are automatically generated when they are needed to ensure the presence of a new key at the end of the lifetime
of a currently active key. At this point, the present options are applied, which may be used for a configuration change.

In the example above, at the day marked `(1)`, it would be detected that key 3 (which just became active) has no
successor. Therefore, one would be created with a pre-publication period starting two days later, as specified by the
lifetime and overlap.

New keys are generated with the same settings (algorithm, key size) as the newest key currently considered (key 4 in the
example). In order to change key parameters, locate this key and replace it with one having the new settings. Any
following key rotation will use those settings.
