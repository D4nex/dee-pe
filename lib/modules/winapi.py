import pefile

class WinApi:
        def __init__(self):
            self.calls = {}
        @staticmethod 
        def parse(file):
            instance = WinApi()
                            
            pe = pefile.PE(file)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
              for index, imp in enumerate(entry.imports):
                instance.calls[index] = imp.name.decode('utf-8') if imp.name else None
            return instance