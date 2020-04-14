import json

from print_object import PrintObject

class PEObject(PrintObject):
    def __init__(self, task, data, hash_engine, create_time, section):
        PrintObject.__init__(self, data, hash_engine)
        self.process = self.get_filename(task)
        self.pid = task.UniqueProcessId
        self.ppid = task.InheritedFromUniqueProcessId
        self.create_time = create_time
        self.section = section
    
    def get_generator(self):
        section_str = 'pe:{0}'.format(self.section) if self.section else 'pe'

        return [
                    str(self.process),
                    int(self.pid),
                    int(self.ppid),
                    str(self.create_time),
                    str(section_str),
                    str(self.get_algorithm()),
                    str(self.get_hash())
                ]

    def get_unified_output(self):
        return [
                    ('Process', '25'),
                    ('Pid', '4'),
                    ('PPid', '4'),
                    ('Create Time', '28'),
                    ('Section', '18'),
                    ('Algorithm', '6'),
                    ('Generated Hash', '100')
                ]

    def _json(self):
        return json.dumps(self._dict())

    def _dict(self):
        ret = {}
        section_str = 'pe:{0}'.format(self.section) if self.section else 'pe'

        ret['Process'] = str(self.process)
        ret['Pid'] = int(self.pid)
        ret['PPid'] = int(self.ppid)
        ret['Create Time'] = str(self.create_time)
        ret['Section'] = str(section_str)
        ret['Algorithm'] = str(self.get_algorithm())
        ret['Generated Hash'] = str(self.get_hash())

        return ret
