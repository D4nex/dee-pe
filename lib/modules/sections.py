import pefile
import math

class Sections:
        def __init__(self):
            self.info = {}
            self.opcodes = {}
        @staticmethod  
        def parse(file):
            def entropy(data):
                pvalue = dict(((chr(x), 0) for x in range(0, 256)))
                for byte in data:
                    pvalue[chr(byte)] +=1
                data_len = len(data)
                entropy = 0.0
                
                for i in pvalue:
                    if pvalue[i] == 0:
                        continue
                    p = float(pvalue[i] / data_len)
                    entropy -= p * math.log(p, 2)
                return entropy
            
            instance = Sections()
            pe = pefile.PE(file, fast_load=True)
            
            for section in pe.sections:
                perms = []
                section_name = section.Name.decode('utf-8').strip('\x00')
                if section.Characteristics & 0x20000000:  # IMAGE_SCN_EXECUTE (0x20000000)
                    perms.append("X")
                    opcodes = section.get_data()
                    instance.opcodes[section_name] = {f'$op': " ".join(f"{byte:02x}" for byte in opcodes[:128])}
                if section.Characteristics & 0x40000000:  # IMAGE_SCN_WRITE (0x40000000)
                    perms.append("W")
                if section.Characteristics & 0x80000000:  # IMAGE_SCN_READ (0x80000000)
                    perms.append("R")
                
                perms_str = ', '.join(perms) if perms else None
                instance.info[section_name] = {
                    "Virtual Address": hex(section.VirtualAddress),
                    "Virtual Size": hex(section.Misc_VirtualSize),
                    "Data Size": hex(section.SizeOfRawData),
                    "Permissions": perms_str,
                    "Entropy": str(entropy(section.get_data()))
                }
            pe.close()
            return instance
                
        
