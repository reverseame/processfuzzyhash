import json

from print_object import PrintObject

from volatility.plugins.vadinfo import PROTECT_FLAGS
from volatility.renderers.basic import Address

class VADObject(PrintObject):
    def __init__(self, task, data, hash_engine, vad, device_name):
        PrintObject.__init__(self, data, hash_engine)
        self.process = self.get_filename(task)
        self.pid = task.UniqueProcessId
        self.ppid = task.InheritedFromUniqueProcessId
        self.start = vad.Start
        self.end = vad.End
        self.protection = vad.VadFlags.Protection
        self.device_name = device_name
    
    def get_generator(self):
        return [
                    str(self.process),
                    int(self.pid),
                    int(self.ppid),
                    Address(self.start),
                    Address(self.end),
                    str(protection_string(self.protection)),
                    str(self.device_name or ''),
                    str(self.get_algorithm()),
                    str(self.get_hash())
                ]

    def get_unified_output(self):
        return [
                    ('Process', '25'),
                    ('Pid', '4'),
                    ('PPid', '4'),
                    ('Start', '[addr]'),
                    ('End', '[addr]'),
                    ('Protection', '22'),
                    ('FileName', '80'),
                    ('Algorithm', '6'),
                    ('Generated Hash', '100')
                ]

    def _json(self):
        return json.dumps(self._dict())

    def _dict(self):
        ret = {}

        ret['Process'] = str(self.process)
        ret['Pid'] = int(self.pid)
        ret['PPid'] = int(self.ppid)
        ret['Start'] = hex(self.start)
        ret['End'] = hex(self.end)
        ret['Protection'] = str(protection_string(self.protection))
        ret['FileName'] = str(self.device_name or '')
        ret['Algorithm'] = str(self.get_algorithm())
        ret['Generated Hash'] = str(self.get_hash())

        return ret


def protection_string(protection):
    return PROTECT_FLAGS.get(protection.v(), hex(protection))
