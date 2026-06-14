# ProcessFuzzyHash - Volatility 3 Plugin

`ProcessFuzzyHash` computes and compares fuzzy hashes of processes in a Windows
memory image. Fuzzy hashes are hashing functions that, contrary to cryptographic
hashes such as MD5, SHA-1 or SHA-256, preserve similarity between similar inputs
(two similar inputs produce similar outputs). Because of how Windows manages
memory, an in-memory instance of an executable is likely to differ from another
instance of the same executable, so fuzzy hashing is well suited to cluster and
compare them.

The plugin lets you choose which part of the process to hash: the main
executable PE, loaded modules (DLLs), individual VAD memory regions, the whole
process address space, or kernel drivers; and, within a PE, specific sections or
headers.

Available fuzzy hash algorithms:
- [ssdeep](https://ssdeep-project.github.io/ssdeep/index.html)
- [sdhash](http://roussev.net/sdhash/sdhash.html)
- [TLSH](https://github.com/trendmicro/tlsh)
- [dcfldd](http://dcfldd.sourceforge.net/) (bundled, pure Python)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

> **Volatility 2?** This is the Volatility 3 / Python 3 port. The original
> (fixed) Volatility 2.6 plugin is preserved on the **`volatility2-latest`**
> branch.

## Installation

Requires [Volatility 3](https://github.com/volatilityfoundation/volatility3)
and Python 3. [`setup.sh`](setup.sh) installs the system libraries, creates a
virtualenv and installs Volatility 3 plus the hashing backends:

```
./setup.sh                      # uses ~/.venv-vol3 by default
VENV=/path/to/venv ./setup.sh   # or pick the virtualenv location
```

Dependencies:
- System: `build-essential`, `cmake`, `libfuzzy-dev`, `libffi-dev`,
  `python3-dev`, `python3-venv`, `ssdeep`
- Python 3: `volatility3`, `pefile`, `python-tlsh`, `ssdeep`, and optionally
  `fuzzyhashlib` (for sdhash)

The hashing libraries are imported lazily: the plugin still loads if one is
missing, and only the affected algorithm is disabled. `dcfldd` is bundled and
needs no external dependency.

## Usage

Pass the plugin directory with `-p` and select a `--mode`:

```
vol -p /path/to/processfuzzyhash -f memory.dmp processfuzzyhash --mode pe --algorithm ssdeep --name svchost.exe
```

### Options

| Option | Description |
| --- | --- |
| `--mode {pe,dll,vad,full,driver}` | What to hash (default `pe`). |
| `--pid <pid> [...]` | Restrict to these process IDs. |
| `--name <name> [...]` | Exact process name match (e.g. `svchost.exe`). |
| `--expression <substr> [...]` | Substring match against the process name. |
| `--algorithm <alg> [...]` | `ssdeep`, `sdhash`, `tlsh`, `dcfldd` (default `ssdeep`). Space- or comma-separated. |
| `--section <sec>` | PE section/header: `.text`, `.data,.rsrc`, `header`, `NT_HEADERS`, `.text:header`, or `all`. |
| `--strings` | Hash printable ASCII strings instead of raw bytes. |
| `--compare <hash> [...]` | Compare each generated hash against the given hash(es); adds a `Rate` column. |
| `--compare-file <path>` | Compare against a file with one hash per line. |
| `--list-sections` | List PE sections instead of hashing (`pe`/`dll`/`driver`). |
| `--dump` | Also write the hashed data to disk (Volatility 3 output dir, see `-o`); adds a `File output` column. |
| `--protection <str> [...]` | `vad`: only hash regions with this protection string. |
| `--executable` | `vad`: only hash executable regions. |
| `--no-device` | `vad`: skip regions backed by a mapped file. |

Notes:
- Supported PE header names: `DOS_HEADER`, `NT_HEADERS`, `FILE_HEADER`,
  `OPTIONAL_HEADER`, `header`.
- Create time is rendered natively by Volatility 3.

### Examples

```
# Main executable of every svchost.exe, with ssdeep
vol -p . -f memory.dmp processfuzzyhash --mode pe --algorithm ssdeep --expression svchost

# Executable VAD regions of lsass with TLSH
vol -p . -f memory.dmp processfuzzyhash --mode vad --executable --algorithm tlsh --name lsass.exe

# .text section of loaded DLLs, comparing against a known hash
vol -p . -f memory.dmp processfuzzyhash --mode dll --section .text --algorithm tlsh --compare T1<...>

# Hash kernel drivers
vol -p . -f memory.dmp processfuzzyhash --mode driver --algorithm ssdeep

# List PE sections of the main executables
vol -p . -f memory.dmp processfuzzyhash --mode pe --list-sections

# Write the dumped PEs to ./out while hashing
vol -p . -o ./out -f memory.dmp processfuzzyhash --mode pe --dump --name lsass.exe
```

Example output (`--mode pe --algorithm ssdeep`, similar svchost.exe instances
produce similar hashes — the point of fuzzy hashing):

```
Process      PID  PPID  Create Time              Section  Algorithm  Generated Hash
svchost.exe  652  536   2022-10-24 12:09:24 UTC  pe       SSDeep     384:bvvWkXZVq+1t5...EbvKrPK
svchost.exe  768  536   2022-10-24 12:09:28 UTC  pe       SSDeep     384:bvvWkXZVq+1t5...EbvKmPK
```

## Volatility 2 → Volatility 3 option mapping

| Vol2 | Vol3 |
| --- | --- |
| `-P` | `--pid` |
| `-N` | `--name` |
| `-E` | `--expression` |
| `-A` | `--algorithm` |
| `-S` | `--section` |
| `-s` | `--strings` |
| `-c` | `--compare` |
| `-C` | `--compare-file` |
| `-X` | `--executable` |
| `--protection`, `--no-device` | unchanged |
| `-T` / `-V` | `--dump` (+ Volatility 3 `-o <dir>`) |
| `-H` | not needed (native datetime) |

## License

Licensed under the [GNU AGPLv3](LICENSE) license.
