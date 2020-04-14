# ProcessFuzzyHash - Volatility Plugin

`ProcessFuzzyHash` for Volatility 2.6 aims at computing fuzzy hashes of processes in a Windows OS dump image. Fuzzy hashes are a subset of hashing functions that, contrary to other (cryptographic) hashing functions such as MD5, SHA-1, or SHA-256, try to preserve similarity between similar inputs (i.e., two similar inputs will generate a similar output). By Windows OS intrinsic characteristics, an instance of
an executable file, i.e, a process, is likely to be different from other instance of the same executable.

This plugin also allows the user to choose the parts of the process to be hashed. Following the Windows PE format, we allow to choose between the whole PE, the full process address space, specific PE (or section) headers, loaded modules and memory pages, among others.

## Installation

You can install all dependencies with [setup.sh](setup.sh):

- System: `python2.7-dev`, `ssdeep`, `libfuzzy-dev`, `cmake`, `libffi-dev`, `libssl1.0.0`, `build-essential`
- Python 2.7: `pycrypto`, `distorm3`, `pefile`, `ssdeep`, `fuzzyhashlib`, `tlsh` (from https://github.com/trendmicro/tlsh)

**NOTE**: Be aware that this script will add [jessie-backports.list](jessie-backports.list) to your sources.

## Usage

```
---------------------------------
Module MalScan
---------------------------------

Calculate and compare Windows processes fuzzy hashes

    Options:
        -P: Process PID(s). Will hash given processes PIDs.
            (-P 252 | -P 252,452,2852)
        -N: Process Name. Will hash process that match given string.
            (-N svchost.exe | -N winlogon.exe,explorer.exe)
        -E: Process expression. Will hash processes that contain given string in the name.
            (-E svchost | -E winlogon,explorer)

        -A: Algorithm to use. Aviable: ssdeep, sdhash, tlsh, dcfldd. Default: ssdeep
            (-A ssdeep | -A SSDeep | -A SSDEEP,sdHash,TLSH,dcfldd)

        --mode:
            pe: main executable module (--mode pe)
            dll: loaded modules (--mode dll)
            vad: memory pages (--mode vad)
            full: whole process address space (--mode full)

        -S: Section to hash
            PE section (-S .text | -S .data,.rsrc)
            PE header (-S header | -S header,NT_HEADERS)
            PE section header (-S .text:header | -S .data,.rsrc:header)

        -s: Hash ASCII strings instead of binary data.

        -c: Compare given hash against generated hashes.
            (E.g. -c '3:elHLlltXluBGqMLWvl:6HRlOBVrl')
        -C: Compare given hashes' file against generated hashes.
            (E.g. -C /tmp/hashfile.txt)

        -H: Human readable values (Create Time)

        -T: Temp folder. Random folder at %TEMP% will be used if none given.
        -V: Keep hashed data on disk. Defaults to False.

        -X: Only show executable pages (--mode vad -X)
        --protection: Filter memory pages by protection string (--mode vad --protection PAGE_EXECUTE_READWRITE)
        --no-device: Don't show memory pages with devices associated (--mode vad --no-device)

        --output-file=<file>: Plugin output will be writen to given file.
        --output=<format>: Output formatting. [text, dot, html, json, sqlite, quick, xlsx]

        --list-sections: Show PE sections

    Note:
        - Supported PE header names (pefile): DOS_HEADER, NT_HEADERS, FILE_HEADER, 
                                            OPTIONAL_HEADER, header
        - Hashes' file given with -C must contain one hash per line.
        - Params -c and -C can be given multiple times (E.g. vol.py (...) -c <hash1> -c <hash2>)"""
```

You need to provide this project path as [first parameter to Volatility](https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage#specifying-additional-plugin-directories):

```
$ python vol.py --plugins /path/to/processfuzzyhash --profile WinProfile -f /path/to/memory.dump processfuzzyhash -A ssdeep -N svchost --mode pe
Volatility Foundation Volatility Framework 2.6

Process     Pid  PPid Create Time Section Algorithm Generated Hash
svchost.exe  440  524 1523815038  pe      SSDeep    384:ivv(...)bvKpK
svchost.exe  660  524 1523815037  pe      SSDeep    384:ivv(...)bvKEK
svchost.exe  764  524 1523815038  pe      SSDeep    384:ivv(...)bvKoK
svchost.exe  848  524 1523815038  pe      SSDeep    384:ivv(...)bvKEK
svchost.exe  904  524 1523815038  pe      SSDeep    384:ivv(...)vKkhK

[... redacted ...]
```

## License

Licensed under the [GNU AGPLv3](LICENSE) license.
