import json

class CompareObject(object):
    def __init__(self, object_, main_hash):
        super(CompareObject, self).__init__()
        self.object = object_
        self.main_hash = main_hash
    
    def get_generator(self):
        return self.object.get_generator() + [
                    str(self.main_hash),
                    str(self.object.compare_hash(self.main_hash, self.object.get_hash()))
                ]

    def get_unified_output(self):
        return self.object.get_unified_output() + [
                    ('Hash', '100'),
                    ('Rate', '3')
                ]

    def _json(self):
        return json.dumps(self._dict())

    def _dict(self):
        ret = self.object._dict()

        ret['Hash'] = str(self.main_hash)
        ret['Rate'] = int(self.object.compare_hash(self.main_hash, self.object.get_hash()))

        return ret
