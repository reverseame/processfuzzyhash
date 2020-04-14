import json

from print_object import PrintObject

from volatility.renderers.basic import Address

class DriverObject(PrintObject):
    def __init__(self, data, mod_base, mod_end, name, hash_engine, section):
        PrintObject.__init__(self, data, hash_engine)
        self.mod_base = mod_base
        self.mod_end = mod_end
        self.name = name
        self.section = section

    def get_generator(self):
        section_str = 'pe:{0}'.format(self.section) if self.section else 'pe'

        return [
                Address(self.mod_base),
                Address(self.mod_end),
                str(self.name),
                str(section_str),
                str(self.get_algorithm()),
                str(self.get_hash())
            ]

    def get_unified_output(self):
        return [
                ('Module Base', '[addr]'),
                ('Module End', '[addr]'),
                ('Module Path', '46'),
                ('Section', '18'),
                ('Algorithm', '6'),
                ('Generated Hash', '100')
            ]

    def _json(self):
        return json.dumps(self._dict())

    def _dict(self):
        ret = {}
        section_str = 'pe:{0}'.format(self.section) if self.section else 'pe'

        ret['Module Base'] = hex(self.mod_base)
        ret['Module End'] = hex(self.mod_end)
        ret['Module Path'] = str(self.name)
        ret['Section'] = str(section_str)
        ret['Algorithm'] = str(self.get_algorithm())
        ret['Generated Hash'] = str(self.get_hash())

        return ret
