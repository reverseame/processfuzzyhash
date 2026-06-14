# This file is part of ProcessFuzzyHash, ported to Volatility 3.
# Licensed under the GNU AGPLv3 license (see LICENSE).
#
# ProcessFuzzyHash computes and compares fuzzy hashes of Windows processes
# found in a memory image. This module is the Volatility 3 port; the original
# Volatility 2 version lives on the `volatility2-latest` branch.
"""Calculate and compare Windows processes fuzzy hashes (Volatility 3)."""

import datetime
import hashlib
import logging
import math
import re
import string
from typing import Iterable, List, Optional

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)

# Optional fuzzy-hash backends. Each is imported lazily so the plugin still
# loads (and the remaining algorithms keep working) when a library is missing.
try:
    import ssdeep as _ssdeep
except ImportError:
    _ssdeep = None
try:
    import tlsh as _tlsh
except ImportError:
    _tlsh = None
try:
    import fuzzyhashlib as _fuzzyhashlib
except ImportError:
    _fuzzyhashlib = None
try:
    import pefile as _pefile
except ImportError:
    _pefile = None

PE_HEADERS = ["DOS_HEADER", "NT_HEADERS", "FILE_HEADER", "OPTIONAL_HEADER", "header"]

_DCFLDD_BLOCKS = 100
_PRINTABLE = frozenset(string.printable.encode("ascii"))


# ---------------------------------------------------------------------------
# dcfldd (piecewise hashing) -- pure Python, no external dependency
# ---------------------------------------------------------------------------
def _dcfldd_hash(data, blocks=_DCFLDD_BLOCKS):
    # Avoid a zero block size on empty input, which would make range() raise.
    bs = max(1, int(math.ceil(len(data) / float(blocks))))
    hashes = [hashlib.md5(data[i:i + bs]).hexdigest() for i in range(0, len(data), bs)]
    # Pad with hashes of zeroed blocks so every digest has `blocks` elements.
    for _ in range(len(hashes), blocks):
        hashes.append(hashlib.md5(b"\x00" * bs).hexdigest())
    return "md5:" + ":".join(hashes)


def _dcfldd_compare(hash1, hash2):
    a = hash1.split(":")
    b = hash2.split(":")
    if a[0] != b[0]:
        return "Error: cannot compare different hash functions"
    if len(a) != len(b):
        return "Error: cannot compare different hash sizes"
    return sum(1 for x, y in zip(a[1:], b[1:]) if x == y)


def _ascii_strings(data, minlen=4):
    """Return the printable ASCII strings in `data` joined by newlines (bytes)."""
    out = []
    cur = bytearray()
    for byte in data:
        if byte in _PRINTABLE:
            cur.append(byte)
            continue
        if len(cur) >= minlen:
            out.append(bytes(cur))
        cur = bytearray()
    if len(cur) >= minlen:
        out.append(bytes(cur))
    return b"\n".join(out)


# ---------------------------------------------------------------------------
# Hash engines
# ---------------------------------------------------------------------------
class _Engine:
    name = ""
    available = True
    requirement = ""

    def calculate(self, data):
        raise NotImplementedError

    def compare(self, hash1, hash2):
        raise NotImplementedError


class _SSDeep(_Engine):
    name = "SSDeep"
    requirement = "the 'ssdeep' python package"
    available = _ssdeep is not None

    def calculate(self, data):
        return _ssdeep.hash(data)

    def compare(self, hash1, hash2):
        try:
            return _ssdeep.compare(hash1, hash2)
        except Exception as reason:  # ssdeep.InternalError and friends
            return "Error: {0}".format(reason)


class _SDHash(_Engine):
    name = "SDHash"
    requirement = "the 'fuzzyhashlib' python package"
    available = _fuzzyhashlib is not None

    def calculate(self, data):
        try:
            return _fuzzyhashlib.sdhash(data).hexdigest().strip()
        except ValueError as reason:
            return "Error: {0} ({1:d})".format(reason, len(data))

    def compare(self, hash1, hash2):
        if hash1.startswith("Error:") or hash2.startswith("Error:"):
            return "0"
        try:
            return _fuzzyhashlib.sdhash(hash=hash1) - _fuzzyhashlib.sdhash(hash=hash2)
        except (ValueError, TypeError) as reason:
            return "Error: {0}".format(reason)


class _TLSH(_Engine):
    name = "TLSH"
    requirement = "the 'tlsh' (python-tlsh) package"
    available = _tlsh is not None

    def calculate(self, data):
        if len(data) < 50:
            return "Error: TLSH requires buffer >= 50 in size ({0:d})".format(len(data))
        fingerprint = _tlsh.hash(data)
        return fingerprint if fingerprint else "Error: empty hash"

    def compare(self, hash1, hash2):
        try:
            return _tlsh.diffxlen(hash1, hash2)
        except (ValueError, TypeError) as reason:
            return "Error: {0}".format(reason)


class _Dcfldd(_Engine):
    name = "dcfldd"
    available = True

    def calculate(self, data):
        return _dcfldd_hash(data)

    def compare(self, hash1, hash2):
        return _dcfldd_compare(str(hash1), str(hash2))


_ENGINES = {
    "ssdeep": _SSDeep,
    "sdhash": _SDHash,
    "tlsh": _TLSH,
    "dcfldd": _Dcfldd,
}


class ProcessFuzzyHash(interfaces.plugins.PluginInterface):
    """Calculate and compare Windows processes fuzzy hashes."""

    _required_framework_version = (2, 0, 0)
    _version = (3, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.ChoiceRequirement(
                name="mode",
                description="What to hash",
                choices=["pe"],
                default="pe",
                optional=True,
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all others excluded)",
                optional=True,
            ),
            requirements.ListRequirement(
                name="name",
                element_type=str,
                description="Exact process name(s) to include (e.g. svchost.exe)",
                optional=True,
            ),
            requirements.ListRequirement(
                name="expression",
                element_type=str,
                description="Substring(s) to match against the process name",
                optional=True,
            ),
            requirements.ListRequirement(
                name="algorithm",
                element_type=str,
                description="Fuzzy hash algorithm(s): ssdeep, sdhash, tlsh, dcfldd",
                default=["ssdeep"],
                optional=True,
            ),
            requirements.StringRequirement(
                name="section",
                description=(
                    "PE section/header to hash (e.g. .text | header | .text:header | all)"
                ),
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="strings",
                description="Hash printable ASCII strings instead of binary data",
                default=False,
                optional=True,
            ),
            requirements.ListRequirement(
                name="compare",
                element_type=str,
                description="Compare every generated hash against the given hash(es)",
                optional=True,
            ),
            requirements.StringRequirement(
                name="compare-file",
                description="File with one hash per line to compare against",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="list-sections",
                description="List PE sections instead of hashing",
                default=False,
                optional=True,
            ),
        ]

    # -- helpers ------------------------------------------------------------
    def _get_engines(self) -> List[_Engine]:
        engines = []
        for alg in self.config["algorithm"]:
            key = alg.lower()
            engine_cls = _ENGINES.get(key)
            if engine_cls is None:
                vollog.error("'%s': invalid fuzzy hash algorithm", alg)
                continue
            engine = engine_cls()
            if not engine.available:
                vollog.error(
                    "'%s': algorithm unavailable, install %s",
                    alg,
                    engine.requirement,
                )
                continue
            engines.append(engine)
        return engines

    def _compare_hashes(self) -> List[str]:
        hashes = []
        if self.config.get("compare", None):
            hashes.extend(self.config["compare"])
        if self.config.get("compare-file", None):
            try:
                with open(self.config["compare-file"]) as handle:
                    hashes.extend(line.strip() for line in handle if line.strip())
            except OSError as reason:
                vollog.error("'%s': %s", self.config["compare-file"], reason)
        return hashes

    def _main_module_name(self, proc) -> str:
        try:
            for entry in proc.load_order_modules():
                try:
                    return str(entry.BaseDllName.get_string())
                except exceptions.InvalidAddressException:
                    break
        except exceptions.InvalidAddressException:
            pass
        # Fall back to the kernel _EPROCESS image name.
        return utility.array_to_string(proc.ImageFileName)

    def _image_base(self, proc) -> Optional[int]:
        try:
            for entry in proc.load_order_modules():
                return int(entry.DllBase)
        except exceptions.InvalidAddressException:
            return None
        return None

    def _selected_processes(self) -> Iterable[interfaces.objects.ObjectInterface]:
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        procs = pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            filter_func=filter_func,
        )

        names = [n.lower() for n in (self.config.get("name", None) or [])]
        exprs = [e.lower() for e in (self.config.get("expression", None) or [])]

        for proc in procs:
            if proc.UniqueProcessId == 4:
                continue
            if not names and not exprs:
                yield proc
                continue
            modname = self._main_module_name(proc).lower()
            if names and any(re.search(r"^{0}$".format(n), modname) for n in names):
                yield proc
            elif exprs and any(e in modname for e in exprs):
                yield proc

    def _reconstruct_pe(self, base: int, layer_name: str) -> bytes:
        """Rebuild the PE image at `base` into a contiguous byte buffer."""
        dos_header = self.context.object(
            self._pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
            offset=base,
            layer_name=layer_name,
        )
        buf = bytearray()
        for offset, data in dos_header.reconstruct():
            end = offset + len(data)
            if end > len(buf):
                buf.extend(b"\x00" * (end - len(buf)))
            buf[offset:end] = data
        return bytes(buf)

    # -- PE section/header selection (pefile based) -------------------------
    @staticmethod
    def _section_name(section) -> str:
        return section.Name.rstrip(b"\x00").decode("ascii", "replace")

    def _section_names(self, pe_obj) -> List[str]:
        return [self._section_name(sec) for sec in pe_obj.sections]

    def _process_section(self, section: Optional[str], pe_data: bytes):
        if not section:
            return [{"section": "", "data": pe_data}]
        if _pefile is None:
            vollog.warning("pefile not available; hashing whole PE instead of a section")
            return [{"section": "", "data": pe_data}]

        try:
            pe_obj = _pefile.PE(data=pe_data, fast_load=True)
        except _pefile.PEFormatError as reason:
            vollog.debug("PEFormatError: %s", reason)
            return []

        requested = [x for x in section.split(",") if x]
        ret = []
        if "all" in requested:
            requested = self._section_names(pe_obj)
            ret.append({"section": "PE", "data": pe_data})

        for sec in set(requested):
            try:
                if sec in PE_HEADERS:
                    entry = self._pe_header(pe_obj, sec)
                else:
                    entry = self._pe_section(pe_obj, sec)
                if entry:
                    ret.append(entry)
            except _pefile.PEFormatError as reason:
                vollog.warning("%s", reason)
        return ret

    def _pe_header(self, pe_obj, header):
        if header == "header":
            # pefile has no '.header' attribute: the headers region spans the
            # start of the image up to SizeOfHeaders.
            size = pe_obj.OPTIONAL_HEADER.SizeOfHeaders
            return {"section": header, "data": bytes(pe_obj.__data__[:size])}
        try:
            data = getattr(pe_obj, header).__pack__()
        except AttributeError:
            vollog.error(
                "'%s': bad header option (DOS_HEADER, NT_HEADERS, FILE_HEADER, "
                "OPTIONAL_HEADER or header)",
                header,
            )
            return None
        return {"section": header, "data": data}

    def _pe_section(self, pe_obj, section):
        search_header = re.search(r"^(.+)(:header)$", section)
        for sec in pe_obj.sections:
            name = self._section_name(sec)
            if search_header and search_header.group(1) == name:
                return {"section": section, "data": sec.__pack__()}
            if section == name:
                return {"section": section, "data": sec.get_data()}
        missing = search_header.group(1) if search_header else section
        raise _pefile.PEFormatError("Section {0} not found".format(missing))

    # -- generators ---------------------------------------------------------
    def _list_sections_generator(self):
        for proc in self._selected_processes():
            pid = int(proc.UniqueProcessId)
            name = self._main_module_name(proc)
            layer_name = proc.add_process_layer()
            base = self._image_base(proc)
            if base is None:
                continue
            try:
                pe_data = self._reconstruct_pe(base, layer_name)
                if _pefile is None:
                    sections = "pefile not available"
                else:
                    pe_obj = _pefile.PE(data=pe_data, fast_load=True)
                    sections = ", ".join(self._section_names(pe_obj))
            except (exceptions.VolatilityException, ValueError) as reason:
                vollog.debug("%s (%d): %s", name, pid, reason)
                continue
            yield (0, (name, pid, sections))

    def _hash_generator(self, engines, compare_hashes):
        strings = self.config["strings"]
        section = self.config.get("section", None)

        for proc in self._selected_processes():
            pid = int(proc.UniqueProcessId)
            ppid = int(proc.InheritedFromUniqueProcessId)
            name = self._main_module_name(proc)
            try:
                ctime = proc.get_create_time()
            except exceptions.VolatilityException:
                ctime = renderers.UnreadableValue()

            layer_name = proc.add_process_layer()
            base = self._image_base(proc)
            if base is None:
                continue

            try:
                pe_data = self._reconstruct_pe(base, layer_name)
            except (exceptions.VolatilityException, ValueError) as reason:
                vollog.debug("%s (%d): %s", name, pid, reason)
                continue

            for sec in self._process_section(section, pe_data):
                data = _ascii_strings(sec["data"]) if strings else sec["data"]
                sec_str = "pe:{0}".format(sec["section"]) if sec["section"] else "pe"
                for engine in engines:
                    digest = engine.calculate(data)
                    base_row = (name, pid, ppid, ctime, sec_str, engine.name, str(digest))
                    if compare_hashes:
                        for other in compare_hashes:
                            rate = engine.compare(other, str(digest))
                            yield (0, base_row + (str(other), str(rate)))
                    else:
                        yield (0, base_row)

    # -- entry point --------------------------------------------------------
    def run(self):
        self._pe_table_name = intermed.IntermediateSymbolTable.create(
            self.context, self.config_path, "windows", "pe", class_types=pe.class_types
        )

        if self.config["list-sections"]:
            columns = [("Process", str), ("PID", int), ("Sections", str)]
            return renderers.TreeGrid(columns, self._list_sections_generator())

        engines = self._get_engines()
        if not engines:
            vollog.error("No usable hash algorithm available")
            return renderers.TreeGrid([("Process", str)], iter(()))

        compare_hashes = self._compare_hashes()
        columns = [
            ("Process", str),
            ("PID", int),
            ("PPID", int),
            ("Create Time", datetime.datetime),
            ("Section", str),
            ("Algorithm", str),
            ("Generated Hash", str),
        ]
        if compare_hashes:
            columns += [("Compared Hash", str), ("Rate", str)]

        return renderers.TreeGrid(columns, self._hash_generator(engines, compare_hashes))
