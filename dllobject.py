import json

from print_object import PrintObject

from volatility.renderers.basic import Address

class DLLObject(PrintObject):
    def __init__(self, task, dump_path, hash_engine, mod_base, mod_end, mod_name, section):
        PrintObject.__init__(self, dump_path, hash_engine)
        self.process = self.get_filename(task)
        self.pid = task.UniqueProcessId
        self.ppid = task.InheritedFromUniqueProcessId
        self.mod_base = mod_base
        self.mod_end = mod_end
        self.mod_name = mod_name
        self.section = section
    
    def get_generator(self):
        mod_name = '{0}:{1}'.format(self.mod_name, self.section) if self.section else self.mod_name

        return [
                    str(self.process),
                    int(self.pid),
                    int(self.ppid),
                    Address(self.mod_base),
                    Address(self.mod_end),
                    str(mod_name),
                    str(self.get_algorithm()),
                    str(self.get_hash())
                ]

    def get_unified_output(self):
        return [
                    ('Process', '25'),
                    ('Pid', '4'),
                    ('PPid', '4'),
                    ('Module Base', '[addr]'),
                    ('Module End', '[addr]'),
                    ('Module Name', '33'),
                    ('Algorithm', '6'),
                    ('Generated Hash', '100')
                ]

    def _json(self):
        return json.dumps(self._dict())

    def _dict(self):
        ret = {}
        mod_name = '{0}:{1}'.format(self.mod_name, self.section) if self.section else self.mod_name

        ret['Process'] = str(self.process)
        ret['Pid'] = int(self.pid)
        ret['PPid'] = int(self.ppid)
        ret['Module Base'] = hex(self.mod_base)
        ret['Module End'] = hex(self.mod_end)
        ret['Module Name'] = str(mod_name)
        ret['Algorithm'] = str(self.get_algorithm())
        ret['Generated Hash'] = str(self.get_hash())

        return ret
