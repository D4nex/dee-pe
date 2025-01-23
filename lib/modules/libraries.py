import pefile

class Imports:
        def __init__(self):
            self.dlls = {}
            self.imphash = None
        @staticmethod
        def parse(file):
            instance = Imports()
            pe = pefile.PE(file)
            instance.imphash = pe.get_imphash()
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8')
                    functions = []
                    for imports in entry.imports:
                        functions.append({
                            "Name": imports.name.decode('utf-8') if imports.name else None,
                            "Address": hex(imports.address) if imports.address else None,
                            })
                            
                    instance.dlls[dll_name] = functions
            return instance