import json

class PESection(object):
    def __init__(self, name, sections, pid='', mod_base=''):
        super(PESection, self).__init__()
        self.name = name
        self.sections = sections
        self.pid = pid
        self.mod_base = mod_base
    
    def get_generator(self):
        name_str = '{0} ({1})'.format(self.name, self.pid) if self.pid and self.name else self.name
        return [
                    str(name_str),
                    str(', '.join(self.sections))
                ]

    def get_unified_output(self):
        return [
                    ('Name', '30'),
                    ('Sections', '100')
                ]

    def _json(self):
        return json.dumps(self._dict())

    def _dict(self):
        ret = {}
        name_str = '{0} ({1})'.format(self.name, self.pid) if self.pid and self.name else self.name

        ret['Name'] = str(name_str)
        ret['Sections'] = str(', '.join(self.sections))

        return ret
