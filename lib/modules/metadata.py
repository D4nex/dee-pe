import pefile
import os


class Metadata:
        def __init__(self):
            self.name = ''
            self.header = "PE"
            self.file_size = None
            self.timestamp = None
            self.file_type = ['PE', 'PE32+']
            self.machine = None
            self.sections = int
            self.characteristics = None
            self.subsystem = None
            self.sym_table = None
            self.sym_num = None
            self.opt_header_size = None

        def to_dict(self):
            return {
                "Name": self.name,
                "Header": self.header,
                "File Size": self.file_size,
                "Time Stamp": self.timestamp,
                "File Type": self.file_type,
                "Machine": self.machine,
                "Pointer to Sym Table": self.sym_table,
                "Number of Sym": self.sym_num,
                "Size of OPT Header": self.opt_header_size,
                "Number of Sections": self.sections,
                "Characteristics": self.characteristics,
                "Subsystem": self.subsystem,
            }
        @staticmethod
        def parse(file):
            pe = pefile.PE(file)
            instance = Metadata()
            instance.name = os.path.basename(file)
            instance.file_size = os.path.getsize(file)
            instance.file_type = (
                "PE" if instance.header in instance.file_type else "None"
            )
            instance.machine = hex(pe.FILE_HEADER.Machine)
            instance.sections = int(pe.FILE_HEADER.NumberOfSections)
            instance.timestamp = pe.FILE_HEADER.TimeDateStamp
            instance.characteristics = hex(pe.FILE_HEADER.Characteristics)
            instance.subsystem = pe.OPTIONAL_HEADER.Subsystem
            instance.sym_table = pe.FILE_HEADER.PointerToSymbolTable
            instance.sym_num = pe.FILE_HEADER.NumberOfSymbols
            instance.opt_header_size = pe.FILE_HEADER.SizeOfOptionalHeader
            return instance