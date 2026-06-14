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
import ntpath
import re
import string
from typing import Iterable, List, Optional

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins.windows import modules, pslist, vadinfo

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
            requirements.VersionRequirement(
                name="vadinfo", component=vadinfo.VadInfo, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="modules", component=modules.Modules, version=(3, 0, 0)
            ),
            requirements.ChoiceRequirement(
                name="mode",
                description="What to hash",
                choices=["pe", "dll", "vad", "full", "driver"],
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
                description="List PE sections instead of hashing (pe/dll/driver)",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Also write the hashed data to disk",
                default=False,
                optional=True,
            ),
            requirements.ListRequirement(
                name="protection",
                element_type=str,
                description="vad: only hash pages with this protection string",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="executable",
                description="vad: only hash executable pages",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="no-device",
                description="vad: skip pages backed by a mapped file/device",
                default=False,
                optional=True,
            ),
        ]

    # -- helpers ------------------------------------------------------------
    def _get_engines(self) -> List[_Engine]:
        engines = []
        # vol3 list options split on spaces ("--algorithm tlsh dcfldd"); also
        # accept the comma syntax ("--algorithm tlsh,dcfldd") for convenience.
        requested = [
            a for entry in self.config["algorithm"] for a in entry.split(",") if a
        ]
        for alg in requested:
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

    # -- output helpers -----------------------------------------------------
    @staticmethod
    def _safe(text) -> str:
        # Keep dump file names filesystem-safe (':' from '<section>:header',
        # path separators, etc.).
        return re.sub(r"[^\w.\-]", "_", str(text))

    def _dump(self, file_name: str, data: bytes) -> str:
        try:
            with self.open(file_name) as handle:
                handle.write(data)
                return handle.preferred_filename
        except Exception as reason:  # noqa: BLE001 - report, never abort the run
            vollog.debug("Unable to write %s: %s", file_name, reason)
            return "Error outputting file"

    # -- memory reading helpers --------------------------------------------
    def _create_time(self, proc):
        try:
            return proc.get_create_time()
        except exceptions.VolatilityException:
            return renderers.UnreadableValue()

    @staticmethod
    def _read_range(layer, start, size):
        """Read [start, start+size) from a layer, padding unmapped pages."""
        chunk = 1024 * 1024 * 10
        out = []
        offset = start
        end = start + size
        while offset < end:
            to_read = min(chunk, end - offset)
            try:
                data = layer.read(offset, to_read, pad=True)
            except exceptions.InvalidAddressException:
                break
            if not data:
                break
            out.append(data)
            offset += to_read
        return b"".join(out)

    def _read_full(self, proc_layer):
        """Read every mapped region of a process address space."""
        out = []
        for mapval in proc_layer.mapping(
            0x0, proc_layer.maximum_address, ignore_errors=True
        ):
            offset, size = mapval[0], mapval[1]
            try:
                data = proc_layer.read(offset, size, pad=True)
            except exceptions.InvalidAddressException:
                continue
            if data:
                out.append(data)
        return b"".join(out)

    def _pe_section_list(self, base, layer_name):
        if _pefile is None:
            return "pefile not available"
        try:
            pe_data = self._reconstruct_pe(base, layer_name)
            pe_obj = _pefile.PE(data=pe_data, fast_load=True)
            return ", ".join(self._section_names(pe_obj))
        except (exceptions.VolatilityException, ValueError, _pefile.PEFormatError) as reason:
            vollog.debug("section list at %#x: %s", base, reason)
            return None

    def _filter_vad(self, protection, file_name):
        wanted = self.config.get("protection", None)
        if wanted and protection not in wanted:
            return True
        if self.config["executable"] and "EXECUTE" not in protection:
            return True
        if self.config["no-device"] and file_name:
            return True
        return False

    # -- per-mode prefix generators ----------------------------------------
    # Each yields (prefix_tuple, data_bytes); _emit_rows appends the
    # algorithm/hash (and compare) columns common to every mode.
    def _pe_prefixes(self):
        section = self.config.get("section", None)
        for proc in self._selected_processes():
            pid = int(proc.UniqueProcessId)
            ppid = int(proc.InheritedFromUniqueProcessId)
            name = self._main_module_name(proc)
            ctime = self._create_time(proc)
            try:
                layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                continue
            base = self._image_base(proc)
            if base is None:
                continue
            try:
                pe_data = self._reconstruct_pe(base, layer_name)
            except (exceptions.VolatilityException, ValueError) as reason:
                vollog.debug("%s (%d): %s", name, pid, reason)
                continue
            for sec in self._process_section(section, pe_data):
                sec_str = "pe:{0}".format(sec["section"]) if sec["section"] else "pe"
                dump_name = "pe.{0}.{1}.{2}.dmp".format(
                    pid, self._safe(name), self._safe(sec["section"] or "pe")
                )
                yield (name, pid, ppid, ctime, sec_str), sec["data"], dump_name

    def _full_prefixes(self):
        for proc in self._selected_processes():
            pid = int(proc.UniqueProcessId)
            ppid = int(proc.InheritedFromUniqueProcessId)
            name = self._main_module_name(proc)
            ctime = self._create_time(proc)
            try:
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                continue
            proc_layer = self.context.layers[proc_layer_name]
            data = self._read_full(proc_layer)
            yield (name, pid, ppid, ctime, "full"), data, "full.{0}.dmp".format(pid)

    def _dll_prefixes(self):
        section = self.config.get("section", None)
        for proc in self._selected_processes():
            pid = int(proc.UniqueProcessId)
            ppid = int(proc.InheritedFromUniqueProcessId)
            name = self._main_module_name(proc)
            try:
                proc_layer_name = proc.add_process_layer()
                entries = list(proc.load_order_modules())
            except exceptions.InvalidAddressException:
                continue
            for entry in entries:
                try:
                    base = int(entry.DllBase)
                    mod_name = str(entry.BaseDllName.get_string())
                    end = base + int(entry.SizeOfImage)
                except exceptions.InvalidAddressException:
                    continue
                try:
                    pe_data = self._reconstruct_pe(base, proc_layer_name)
                except (exceptions.VolatilityException, ValueError) as reason:
                    vollog.debug("%s (%d) %s: %s", name, pid, mod_name, reason)
                    continue
                for sec in self._process_section(section, pe_data):
                    label = (
                        "{0}:{1}".format(mod_name, sec["section"])
                        if sec["section"]
                        else mod_name
                    )
                    prefix = (
                        name,
                        pid,
                        ppid,
                        format_hints.Hex(base),
                        format_hints.Hex(end),
                        label,
                    )
                    dump_name = "dll.{0}.{1}.{2:#x}.{3}.dmp".format(
                        pid, self._safe(mod_name), base, self._safe(sec["section"] or "pe")
                    )
                    yield prefix, sec["data"], dump_name

    def _vad_prefixes(self):
        kernel = self.context.modules[self.config["kernel"]]
        protect_values = vadinfo.VadInfo.protect_values(
            self.context, kernel.layer_name, kernel.symbol_table_name
        )

        def size_filter(vad):
            # Skip any region larger than 1 GiB (matches the original plugin).
            try:
                return vad.get_size() >= 0x40000000
            except exceptions.InvalidAddressException:
                return True

        for proc in self._selected_processes():
            pid = int(proc.UniqueProcessId)
            ppid = int(proc.InheritedFromUniqueProcessId)
            name = self._main_module_name(proc)
            try:
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                continue
            proc_layer = self.context.layers[proc_layer_name]
            for vad in vadinfo.VadInfo.list_vads(proc, filter_func=size_filter):
                try:
                    start = vad.get_start()
                    end = vad.get_end()
                    size = vad.get_size()
                    protection = vad.get_protection(
                        protect_values, vadinfo.winnt_protections
                    )
                except exceptions.InvalidAddressException:
                    continue
                file_name = vad.get_file_name()
                file_str = (
                    ""
                    if isinstance(file_name, interfaces.renderers.BaseAbsentValue)
                    else str(file_name)
                )
                if self._filter_vad(protection, file_str):
                    continue
                data = self._read_range(proc_layer, start, size)
                prefix = (
                    name,
                    pid,
                    ppid,
                    format_hints.Hex(start),
                    format_hints.Hex(end),
                    protection,
                    file_str,
                )
                dump_name = "vad.{0}.{1:#x}-{2:#x}.dmp".format(pid, start, end)
                yield prefix, data, dump_name

    def _driver_prefixes(self):
        section = self.config.get("section", None)
        session_layers = list(
            modules.Modules.get_session_layers(
                context=self.context, kernel_module_name=self.config["kernel"]
            )
        )
        for mod in modules.Modules.list_modules(
            self.context, kernel_module_name=self.config["kernel"]
        ):
            base = int(mod.DllBase)
            end = base + int(mod.SizeOfImage)
            try:
                path = str(mod.FullDllName.get_string())
            except exceptions.InvalidAddressException:
                path = ""
            session_layer_name = modules.Modules.find_session_layer(
                self.context, session_layers, base
            )
            if not session_layer_name:
                continue
            try:
                pe_data = self._reconstruct_pe(base, session_layer_name)
            except (exceptions.VolatilityException, ValueError) as reason:
                vollog.debug("driver %#x: %s", base, reason)
                continue
            for sec in self._process_section(section, pe_data):
                sec_str = "pe:{0}".format(sec["section"]) if sec["section"] else "pe"
                prefix = (
                    format_hints.Hex(base),
                    format_hints.Hex(end),
                    path,
                    sec_str,
                )
                dump_name = "driver.{0:#x}.{1}.{2}.dmp".format(
                    base,
                    self._safe(ntpath.basename(path) or "driver"),
                    self._safe(sec["section"] or "pe"),
                )
                yield prefix, sec["data"], dump_name

    # -- common row emitter ------------------------------------------------
    def _emit_rows(self, prefixes, engines, compare_hashes):
        strings = self.config["strings"]
        dump = self.config["dump"]
        for prefix, data, dump_name in prefixes:
            # Persist the raw data once per blob (not once per algorithm).
            tail = (self._dump(dump_name, data),) if dump else ()
            blob = _ascii_strings(data) if strings else data
            for engine in engines:
                digest = str(engine.calculate(blob))
                row = prefix + (engine.name, digest)
                if compare_hashes:
                    for other in compare_hashes:
                        rate = engine.compare(other, digest)
                        yield (0, row + (str(other), str(rate)) + tail)
                else:
                    yield (0, row + tail)

    # -- list-sections ------------------------------------------------------
    def _list_sections_generator(self):
        mode = self.config["mode"]
        if mode == "dll":
            for proc in self._selected_processes():
                pid = int(proc.UniqueProcessId)
                try:
                    proc_layer_name = proc.add_process_layer()
                    entries = list(proc.load_order_modules())
                except exceptions.InvalidAddressException:
                    continue
                for entry in entries:
                    try:
                        base = int(entry.DllBase)
                        mod_name = str(entry.BaseDllName.get_string())
                    except exceptions.InvalidAddressException:
                        continue
                    secs = self._pe_section_list(base, proc_layer_name)
                    if secs is not None:
                        yield (0, ("{0} ({1})".format(mod_name, pid), secs))
        elif mode == "driver":
            session_layers = list(
                modules.Modules.get_session_layers(
                    context=self.context, kernel_module_name=self.config["kernel"]
                )
            )
            for mod in modules.Modules.list_modules(
                self.context, kernel_module_name=self.config["kernel"]
            ):
                base = int(mod.DllBase)
                try:
                    mod_name = str(mod.BaseDllName.get_string())
                except exceptions.InvalidAddressException:
                    mod_name = ""
                session_layer_name = modules.Modules.find_session_layer(
                    self.context, session_layers, base
                )
                if not session_layer_name:
                    continue
                secs = self._pe_section_list(base, session_layer_name)
                if secs is not None:
                    yield (0, (mod_name, secs))
        else:  # pe
            for proc in self._selected_processes():
                pid = int(proc.UniqueProcessId)
                name = self._main_module_name(proc)
                try:
                    layer_name = proc.add_process_layer()
                except exceptions.InvalidAddressException:
                    continue
                base = self._image_base(proc)
                if base is None:
                    continue
                secs = self._pe_section_list(base, layer_name)
                if secs is not None:
                    yield (0, ("{0} ({1})".format(name, pid), secs))

    # -- entry point --------------------------------------------------------
    def run(self):
        self._pe_table_name = intermed.IntermediateSymbolTable.create(
            self.context, self.config_path, "windows", "pe", class_types=pe.class_types
        )

        mode = self.config["mode"]

        if self.config["list-sections"]:
            columns = [("Name", str), ("Sections", str)]
            if mode in ("vad", "full"):
                vollog.error("--list-sections is not supported for mode '%s'", mode)
                return renderers.TreeGrid(columns, iter(()))
            return renderers.TreeGrid(columns, self._list_sections_generator())

        engines = self._get_engines()
        if not engines:
            vollog.error("No usable hash algorithm available")
            return renderers.TreeGrid([("Process", str)], iter(()))

        compare_hashes = self._compare_hashes()

        proc_cols = [("Process", str), ("PID", int), ("PPID", int)]
        if mode == "pe":
            columns = proc_cols + [("Create Time", datetime.datetime), ("Section", str)]
            prefixes = self._pe_prefixes()
        elif mode == "full":
            columns = proc_cols + [("Create Time", datetime.datetime), ("Section", str)]
            prefixes = self._full_prefixes()
        elif mode == "dll":
            columns = proc_cols + [
                ("Module Base", format_hints.Hex),
                ("Module End", format_hints.Hex),
                ("Module Name", str),
            ]
            prefixes = self._dll_prefixes()
        elif mode == "vad":
            columns = proc_cols + [
                ("Start", format_hints.Hex),
                ("End", format_hints.Hex),
                ("Protection", str),
                ("FileName", str),
            ]
            prefixes = self._vad_prefixes()
        else:  # driver
            columns = [
                ("Module Base", format_hints.Hex),
                ("Module End", format_hints.Hex),
                ("Module Path", str),
                ("Section", str),
            ]
            prefixes = self._driver_prefixes()

        columns = columns + [("Algorithm", str), ("Generated Hash", str)]
        if compare_hashes:
            columns += [("Compared Hash", str), ("Rate", str)]
        if self.config["dump"]:
            columns += [("File output", str)]

        return renderers.TreeGrid(columns, self._emit_rows(prefixes, engines, compare_hashes))
