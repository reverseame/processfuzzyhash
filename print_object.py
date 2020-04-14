class PrintObject(object):
    def __init__(self, data, hash_engine):
        super(PrintObject, self).__init__()
        self.data = data
        self.hash_engine = hash_engine
        self._hash = None

    def get_filename(self, task):
        for mod in task.get_load_modules():
            return mod.BaseDllName

    def get_hash(self):
        self._hash = self.hash_engine.calculate(data=self.data) if not self._hash else self._hash

        return self._hash

    def get_algorithm(self):
        return self.hash_engine.get_algorithm()

    def compare_hash(self, hash1, hash2):
        return self.hash_engine.compare(hash1, hash2)
