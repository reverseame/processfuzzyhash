import os
import re
import pefile

import volatility.obj as obj
import volatility.debug as debug
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.constants as constants
import volatility.exceptions as exceptions
import volatility.win32.modules as modules
from volatility.plugins.common import AbstractWindowsCommand

from peobject import PEObject
from dllobject import DLLObject
from pe_section import PESection
from driverobject import DriverObject
from compareobject import CompareObject
from vadobject import VADObject, protection_string
from hashengine import HashEngine, InvalidAlgorithm

PE_HEADERS = ['DOS_HEADER', 'NT_HEADERS', 'FILE_HEADER', 'OPTIONAL_HEADER', 'header']

class ProcessFuzzyHash(AbstractWindowsCommand):
    """
        Calculate and compare Windows processes fuzzy hashes

        Options:
          -P: Process PID(s). Will hash given processes PIDs.
                (-P 252 | -P 252,452,2852)
          -N: Process Name. Will hash process that match given string.
                (-N svchost.exe | -N winlogon.exe,explorer.exe)
          -E: Process expression. Will hash processes that contain given string in the name.
                (-E svchost | -E winlogon,explorer)

          -A: Algorithm to use. Available: ssdeep, sdhash, tlsh, dcfldd. Default: ssdeep
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
          - Params -c and -C can be given multiple times (E.g. vol.py (...) -c <hash1> -c <hash2>)
    """

    def __init__(self, config, *args, **kwargs):
        AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('PID', short_option='P', help='Process ID', action='store',type='str')
        self._config.add_option('PROC-EXPRESSION', short_option='N', help='Expression containing process name', action='store', type='str')
        self._config.add_option('PROC-NAME', short_option='E', help='Process name', action='store', type='str')
        self._config.add_option('ALGORITHM', short_option='A', default='ssdeep', help='Hash algorithm', action='store', type='str')
        self._config.add_option('MODE', help='Dump mode: pe, dll, vad, full', action='store', type='str')
        self._config.add_option('SECTION', short_option='S', help='PE section to hash', action='store', type='str')
        self._config.add_option('PROTECTION', help='Filter VAD by protection', action='append', type='str')
        self._config.add_option('EXECUTABLE', short_option='X', help='Only show executable pages (VAD)', action='store_true')
        self._config.add_option('COMPARE-HASH', short_option='c', help='Compare to given hash', action='append', type='str')
        self._config.add_option('COMPARE-FILE', short_option='C', help='Compare to hashes\' file', action='append', type='str')
        self._config.add_option('HUMAN-READABLE', short_option='H', help='Show human readable values', action='store_true')
        self._config.add_option('STRINGS', short_option='s', help='Hash strings contained in binary data', action='store_true')
        self._config.add_option('TMP-FOLDER', short_option='T', help='Temp folder to write all data', action='store', type='str')
        self._config.add_option('NO-DEVICE', help='Don\'t show memory pages with devices associated', action='store_true')
        self._config.add_option('LIST-SECTIONS', help='Show PE sections', action='store_true')
        self._config.add_option('JSON', help='Print JSON output', action='store_true')

    def calculate(self):
        """Main volatility plugin function"""
        try:
            self.addr_space = utils.load_as(self._config)
            self.validate_options()

            self.hash_engines = self.get_hash_engines()

            pids = self.get_processes()
            if not pids:
                debug.error('{0}: Could not find any processes with those options'.format(self.get_plugin_name()))

            # Get hashes to compare to
            hashes = []
            if self._config.COMPARE_HASH:
                hashes = self._config.COMPARE_HASH[0].split(',')
            elif self._config.COMPARE_FILE:
                hashes = self.read_hash_files(self._config.COMPARE_FILE[0].split(','))

            for dump in self.make_dumps(pids, self._config.MODE):
                if hashes:
                    for item in self.compare_hash(dump, hashes):
                        yield item
                else:
                    yield dump

        except KeyboardInterrupt:
            debug.error('KeyboardInterrupt')

    def validate_options(self):
        # MODE is mandatory
        if self._config.MODE:
            return
        debug.error('{0}: You must specify something to do (--mode or -h)'.format(self.get_plugin_name()))

    def get_hash_engines(self):
        ret = []

        algorithms = self._config.ALGORITHM.split(',')
        for alg in algorithms:
            try:
                ret += [HashEngine(alg, self._config.STRINGS)]
            except InvalidAlgorithm, reason:
                debug.error('{0}: \'{1}\': {2}'.format(self.get_plugin_name(), alg, reason))
        return ret

    def get_processes(self):
        """
        Return all processes id by either name, expresion or pids

        @returns a list containing all desired pids
        """

        pids = []

        if self._config.PROC_NAME:
            names = self._config.PROC_NAME.split(',')
            pids = self.get_proc_by_name(names)
        elif self._config.PROC_EXPRESSION:
            # Prepare all processes names as regular expresions
            names = '.*{0}.*'.format(self._config.PROC_EXPRESSION.replace(',', '.*,.*')).split(',')
            pids = self.get_proc_by_name(names)
        else:
            pids = self.get_proc_by_pid(self._config.PID)

        return pids

    def get_proc_by_name(self, names):
        """
        Search all processes by process name

        @para names: a list with all names to search

        @returns a list of pids
        """

        ret = []

        for proc in tasks.pslist(self.addr_space):
            for name in names:
                if re.search(r'^{0}$'.format(name), str(self.get_exe_module(proc)), flags=re.IGNORECASE):
                    ret += [proc.UniqueProcessId]

        return ret

    def get_exe_module(self, task):
        """
        Return main exe module name

        @para task: process

        @returns exe filename
        """
        for mod in task.get_load_modules():
            return mod.BaseDllName

    def get_proc_by_pid(self, pids):
        """
        Search all processes which its pid matches

        @para names: a list with all pids to search

        @returns a list of pids
        """

        ret = []

        if pids:
            pids = pids.split(',')
            for proc in tasks.pslist(self.addr_space):
                # Check if those pids exist in memory dump file
                if str(proc.UniqueProcessId) in pids:
                    ret += [proc.UniqueProcessId]
        else:
            # Return all pids if none is provided
            for proc in tasks.pslist(self.addr_space):
                # Only return those which are currently running
                if not proc.ExitTime:
                    ret += [proc.UniqueProcessId]
        
        return [x for x in ret if x != 4]

    def make_dumps(self, pids, mode):
        """
        Generate all dumps files

        @param pids: processes to dump
        @param mode: section mode

        @return list of objects implementing PrintObject interface
        """

        self._config.TMP_FOLDER = self.prepare_working_dir()

        # Generate dump files depending on section mode provided
        if mode == 'pe':
            for item in self.pe_dump(pids):
                yield item
        elif mode == 'dll':
            for item in self.dll_dump(pids):
                yield item
        elif mode == 'vad':
            for item in self.vad_dump(pids):
                yield item
        elif mode == 'driver':
            for item in self.driver_dump():
                yield item
        elif mode == 'full':
            for item in self.full_dump(pids):
                yield item
        
    def full_dump(self, pids):
        """
        Generate single dump files containing all memory pages of processes

        @param pids: pid list to dump

        @returns a list of PEObject
        """

        for task in tasks.pslist(self.addr_space):
            if task.UniqueProcessId in pids:
                task_space = task.get_process_address_space()
                create_time = str(task.CreateTime) if self._config.HUMAN_READABLE else int(task.CreateTime)
                pe_full_data = self.get_all_pe_pages(task_space)
                for engine in self.hash_engines:
                    yield PEObject(task, pe_full_data, engine, create_time, 'full')
                    if self._config.TMP_FOLDER:
                        dump_path = os.path.join(self._config.TMP_FOLDER, '{0}.dmp'.format(str(task.UniqueProcessId)))
                        self.backup_file(dump_path, pe_full_data)

    def get_all_pe_pages(self, ps_space):
        """
        Write all available memory pages of a process address space to a
        single file

        @param ps_space: process address space
        """
        ret = b''

        pages = ps_space.get_available_pages()
        if pages:
            for page in pages:
                data = ps_space.read(page[0], page[1])
                if data:
                    ret += data

        return ret

    def driver_dump(self):
        procs = list(tasks.pslist(self.addr_space))
        mods = dict((mod.DllBase.v(), mod) for mod in modules.lsmod(self.addr_space))
        for mod in mods.values():
            mod_base = mod.DllBase.v()
            mode_end = mod_base + mod.SizeOfImage
            space = tasks.find_space(self.addr_space, procs, mod_base)
            if space:
                pe_data = self.get_pe_content(space, mod_base)
                if self._config.LIST_SECTIONS:
                    yield PESection(mod.BaseDllName, self.get_pe_sections(pe_data))
                else:
                    sections = self.process_section(None, self._config.SECTION, pe_data)
                    for sec in sections:
                        for engine in self.hash_engines:
                            yield DriverObject(sec['data'], mod_base, mode_end, mod.FullDllName, engine, sec['section'])
                            if self._config.TMP_FOLDER:
                                dump_path = os.path.join(self._config.TMP_FOLDER, 'driver.{0:x}.{1}{2}.sys'.format(mod_base, mod.BaseDllName, sec['section']))
                                self.backup_file(dump_path, sec['data'])

    def pe_dump(self, pids):
        """
        Generate dump files containing the PE

        @param pids: pid list to dump
        @param section: process section

        @returns a list of PEObject sorted by pid
        """

        for task in tasks.pslist(self.addr_space):
            if task.UniqueProcessId in pids:
                task_space = task.get_process_address_space()
                # Check if _PEB is available and not paged
                if task_space and task.Peb and task_space.vtop(task.Peb.ImageBaseAddress):
                    pe_data = self.get_pe_content(task_space, task.Peb.ImageBaseAddress)
                    create_time = str(task.CreateTime) if self._config.HUMAN_READABLE else int(task.CreateTime)
                    try:
                        if self._config.LIST_SECTIONS:
                            yield PESection(self.get_exe_module(task), self.get_pe_sections(pe_data), task.UniqueProcessId)
                        else:
                            # Generate one dump Object for every section/header specified
                            sections = self.process_section(task, self._config.SECTION, pe_data)
                            for sec in sections:
                                for engine in self.hash_engines:
                                    yield PEObject(task, sec['data'], engine, create_time, sec['section'])
                                    if self._config.TMP_FOLDER:
                                        dump_path = os.path.join(self._config.TMP_FOLDER, 'executable.{0}.{1}{2}.exe'.format(task.UniqueProcessId, task.ImageFileName, sec['section']))
                                        self.backup_file(dump_path, sec['data'])
                    except pefile.PEFormatError, reason:
                        debug.warning('{0}: {1} ({2}): {3}'.format(self.get_plugin_name(), task.ImageFileName, task.UniqueProcessId, reason))

    def get_pe_content(self, space, base):
        ret = b''
        pe_file = obj.Object('_IMAGE_DOS_HEADER', offset=base, vm=space)

        try:
            for offset, code in pe_file.get_image():
                ret += code
        except (ValueError, exceptions.SanityCheckException):
            pass

        return ret

    def get_pe_sections(self, pe_data):
        ret = []
        pe = pefile.PE(data=pe_data, fast_load=True)

        for sec in pe.sections:
            ret += [sec.Name.translate(None, '\x00')]

        return ret

    def process_section(self, task, section, pe_data):
        """
        Generate one dump file for every section

        @param task: process
        @param section: sections to dump
        @param pe_data: PE data

        @returns a list of dicts containing each section and dump path associated
        """
        if not section:
            return [{'section': '', 'data': pe_data}]

        ret = []

        try:
            pe = pefile.PE(data=pe_data, fast_load=True)
            sections = [x for x in section.split(',') if x]

            if 'all' in sections:
                sections = self.get_pe_sections(pe_data)
                ret = [{'section': 'PE', 'data': pe_data}]

            sections = list(set(sections))

            for sec in sections:
                try:
                    if sec in PE_HEADERS:
                        # PE header
                        ret += [self.process_pe_header(pe, sec)]
                    else:
                        # PE section
                        ret += [self.process_pe_section(pe, sec)]                    
                except pefile.PEFormatError, reason:
                    if task:
                        debug.warning('{0}: {1} ({2}): {3}'.format(self.get_plugin_name(), task.ImageFileName, task.UniqueProcessId, reason))
                    else:
                        debug.warning('{0}: {1}'.format(self.get_plugin_name(), reason))
        except pefile.PEFormatError:
            pass

        return ret

    def process_pe_header(self, pe, header):
        """
        Retrieve desired PE header

        @param pe: PE object
        @param header: PE header to search

        @return a dict containing header and dump file associated
        """

        try:
            if header == 'header':
                data = pe.__getattribute__(header)
            else:
                # Try to get specified PE header
                data = pe.__getattribute__(header).__pack__()
            return {'section': header, 'data': data}
        except AttributeError:
                debug.error('{0}: \'{1}\': Bad header option (DOS_HEADER, NT_HEADERS, FILE_HEADER, OPTIONAL_HEADER or header)'.format(self.get_plugin_name(), header.split(':')[-1]))

    def process_pe_section(self, pe, section):
        """
        Retrieve desired PE section

        @param pe: PE object
        @param header: PE section to search

        @return a dict containing section and dump file associated
        """

        search_header = re.search(r'^(.+)(:header)$', section)

        # Iterate through all existing PE sections
        for sec in pe.sections:
            if search_header and search_header.group(1) == sec.Name.translate(None, '\x00'):
                # Get section header
                return {'section': section, 'data': sec.__pack__()}
            elif section == sec.Name.translate(None, '\x00'):
                # Get section data
                return {'section': section, 'data': sec.get_data()}

        header = search_header.group(1) if search_header else section
        raise pefile.PEFormatError('Section {0} not found'.format(header))

    def vad_dump(self, pids):
        """
        Generate dump files containing all process pages based on its Virtual Address Descriptors

        @param pids: pid list to dump

        @returns a list of VADObject sorted by (pid, vad.StartAddress)
        """

        # Filter any page bigger than 1GB
        filter = lambda x: x.Length < 0x40000000

        for task in tasks.pslist(self.addr_space):
            if task.UniqueProcessId in pids:
                # Walking the VAD tree can be done in kernel AS, but to 
                # carve the actual data, we need a valid process AS.
                task_space = task.get_process_address_space()
                if task_space:
                    for vad, _ in task.get_vads(vad_filter=filter, skip_max_commit=True):
                        if vad:
                            devicename = ''
                            try:
                                # Try to get associated VAD module
                                devicename = vad.FileObject.file_name_with_device()
                            except AttributeError:
                                pass
                            if self.filter_vad(protection_string(vad.VadFlags.Protection), devicename):
                                continue
                            vad_data = self.get_vad_content(vad, task_space)
                            for engine in self.hash_engines:
                                yield VADObject(task, vad_data, engine, vad, devicename)
                                if self._config.TMP_FOLDER:
                                    dump_path = os.path.join(self._config.TMP_FOLDER, '{0}.{1}.{2:x}-{3:x}.dmp'.format(task.ImageFileName, task.UniqueProcessId, vad.Start, vad.End))
                                    self.backup_file(dump_path, vad_data)

    def get_vad_content(self, vad, address_space):
        ret = b''
        offset = vad.Start
        out_of_range = vad.Start + vad.Length 
        while offset < out_of_range:
            to_read = min(constants.SCAN_BLOCKSIZE, out_of_range - offset)
            data = address_space.zread(offset, to_read)
            if not data: 
                break
            ret += data
            offset += to_read

        return ret

    def filter_vad(self, protection, devicename):
        if self._config.PROTECTION and (protection not in self._config.PROTECTION):
            return True
        if self._config.EXECUTABLE:
            # Check if VAD's protection is executable
            if not 'EXECUTE' in protection:
                return True
        if self._config.NO_DEVICE and devicename:
            # Skip VADs with module associated
            return True

        return False

    def dll_dump(self, pids):
        """
        Generate dump files containing all modules loaded by a process

        @param pids: pid list to dump

        @returns a list of DLLObject sorted by (pid, mod.BaseAddress)
        """
        for task in tasks.pslist(self.addr_space):
            if task.UniqueProcessId in pids:
                task_space = task.get_process_address_space()
                mods = dict((mod.DllBase.v(), mod) for mod in task.get_load_modules())
                for mod in mods.values():
                    mod_base = mod.DllBase.v()
                    mod_end = mod_base + mod.SizeOfImage
                    if task_space.is_valid_address(mod_base):
                        mod_name = mod.BaseDllName
                        pe_data = self.get_pe_content(task_space, mod_base)
                        if self._config.LIST_SECTIONS:
                            yield PESection(mod_name, self.get_pe_sections(pe_data), task.UniqueProcessId, mod_base)
                        else:
                            # Generate one dump Object for every section/header specified
                            sections = self.process_section(task, self._config.SECTION, pe_data)
                            for sec in sections:
                                for engine in self.hash_engines:
                                    yield DLLObject(task, sec['data'], engine, mod_base, mod_end, mod_name, sec['section'])
                                    if self._config.TMP_FOLDER:
                                        dump_path = os.path.join(self._config.TMP_FOLDER, 'module.{0}.{1}.{2}{3}.{4:x}.dll'.format(task.ImageFileName, task.UniqueProcessId, mod_name, sec['section'], mod_base))
                                        self.backup_file(dump_path, sec['data'])

    def compare_hash(self, dump, hash_):
        """Compare hash for every dump Object"""

        for h in hash_:
            yield CompareObject(dump, h)

    def read_hash_files(self, paths):
        ret = []

        try:
            for path in paths:
                with open(path) as f:
                    ret += [x.strip() for x in f.readlines()]
        except IOError:
            debug.error('{0}: \'{1}\': Can not open file'.format(self.get_plugin_name(), path))

        return ret

    def backup_file(self, path, data):
        with open(path, 'wb') as f:
            return f.write(data)

    def prepare_working_dir(self):
        if self._config.TMP_FOLDER:
            temp_path = os.path.realpath(self._config.TMP_FOLDER)
            if not os.path.exists(temp_path):
                os.makedirs(temp_path)
            return temp_path
        else:
            return ''

    def render_text(self, outfd, data):
        first = True
        for item in data:
            if self._config.json: 
                outfd.write('{0}\n'.format(item._json()))
            else:
                if first:
                    self.table_header(outfd, item.get_unified_output())
                    first = False
                # Transform list to arguments with * operator
                self.table_row(outfd, *item.get_generator())

    def get_plugin_name(self):
        return os.path.splitext(os.path.basename(__file__))[0]
