# Grand Nullifier

Overwrites files in place, then renames, truncates and deletes them. A small
library (`grandnullifier.h`) and a console tool (`nullifier`), in pure C11
with no dependencies, for Windows, Linux, macOS, FreeBSD, OpenBSD and NetBSD.
Paths are UTF-8 everywhere.

## Methods

| Method | Passes | Writes | Standard |
|---|---|---|---|
| `standard` | 1 | random | NIST SP 800-88 Clear |
| `enhanced` | 3 | 0x00, 0xFF, random | US Air Force AFSSI-5020 |
| `professional` | 7 + verify | 0x00/0xFF three times, random, read back | Canadian RCMP TSSIT OPS-II |
| `ultimate` | 33 | random | Pfitzner |

On a modern hard drive one pass is as effective as 33; the longer methods are
there for policies that name them. Random data comes from xoshiro256**, seeded
by the system (`BCryptGenRandom`, `/dev/urandom`), which also lets the verify
pass regenerate what was written.

## What no file wiper can do

On SSDs and other flash (wear levelling), on copy-on-write or snapshotting
file systems (APFS, Btrfs, ZFS, Windows shadow copies) and in cloud-synced
folders, older copies of the data can survive elsewhere, whatever the number
of passes. There, only full-disk encryption makes deletion reliable.

## Console

```
nullifier [-m METHOD] [-r] [-y] [-q] PATH...
nullifier --list
```

It asks before wiping unless given `-y`. Links, junctions and devices are never
followed; folders need `-r`. Exit 0 when everything was wiped, 1 otherwise,
2 for a usage error.

## Library

```c
#include "grandnullifier.h"

int rc = gn_wipe_file(path, GN_ENHANCED, 0, progress, user);
if (rc != GN_OK) fprintf(stderr, "%s\n", gn_strerror(rc));
```

`progress(user, pass, passes, done, total)` is called as it writes; return
non-zero to stop. With CMake, `add_subdirectory(grandnullifier)` and link
`grandnullifier`; the tool and tests build only when it is the top project.

## Build

```
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

## License

MIT
