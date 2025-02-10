from colorama import Fore, Style
import pefile

class PEParser:
  def __init__(self, master):
    self.pe = pefile.PE(master.file)
    self.dos_hdr = self.pe.DOS_HEADER
    self.file_hdr = self.pe.FILE_HEADER
    self.opt_hdr = self.pe.OPTIONAL_HEADER
    PEParser.parseDosHdr(self)
    PEParser.parseFileHdr(self)
    PEParser.parseOptHeader(self)
    
  
  def parseDosHdr(self):
    print("\n\tstruct", Fore.MAGENTA + Style.DIM, "IMAGE_DOS_HEADER", Style.RESET_ALL, "{")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_magic:04X}{Style.RESET_ALL}  ->  Magic Number")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_cblp:04X}{Style.RESET_ALL}  ->  Bytes on last page of file")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_cp:04X}{Style.RESET_ALL}  ->  Pages in file")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_crlc:04X}{Style.RESET_ALL}  ->  Number of Relocations")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_cparhdr:04X}{Style.RESET_ALL}  ->  Header size in paragraphs")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_minalloc:04X}{Style.RESET_ALL}  ->  Minimum extra paragraphs needed")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_maxalloc:04X}{Style.RESET_ALL}  ->  Maximum extra paragraphs needed")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_ss:04X}{Style.RESET_ALL}  ->  Initial value of SS register(Stack segment)")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_sp:04X}{Style.RESET_ALL}  ->  Initial value of SP register(Stack pointer)")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_csum:04X}{Style.RESET_ALL}  ->  Checksum")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_ip:04X}{Style.RESET_ALL}  ->  Initial value of IP register(Instruction pointer)")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_cs:04X}{Style.RESET_ALL}  ->  Initial value of CS register(Code segment)")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_lfarlc:04X}{Style.RESET_ALL}  ->  Offset of relocation table")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_ovno:04X}{Style.RESET_ALL}  ->  Overlay number")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_oemid:04X}{Style.RESET_ALL}  ->  OEM identifier")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_oeminfo:04X}{Style.RESET_ALL}  ->  OEM information")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_lfanew:04X}{Style.RESET_ALL}  ->  File addr of new exe header")
    print("\t};")
  
  def parseFileHdr(self):
    print("\n\tstruct", Fore.MAGENTA + Style.DIM, "IMAGE_FILE_HEADER", Style.RESET_ALL, "{")
    machine = self.file_hdr.Machine
    machine_dict = {
        0x8664: "x64",
        0x014C: "x86",
        0x0200: "ARM",
        0x04C0: "MIPS"
    }
    print(f"\t\t  {Fore.CYAN}{machine_dict.get(machine, 'UNKNOWN')}{Style.RESET_ALL}   ->  Machine")
    print(f"\t\t  {Fore.CYAN}{self.file_hdr.NumberOfSections:04X}{Style.RESET_ALL}  ->  Number of sections")
    print(f"\t\t  {Fore.CYAN}{self.file_hdr.TimeDateStamp:04X}{Style.RESET_ALL} -> Timestamp")
    print(f"\t\t  {Fore.CYAN}{self.file_hdr.PointerToSymbolTable:04X}{Style.RESET_ALL}  ->  Pointer to sym table")
    print(f"\t\t  {Fore.CYAN}{self.file_hdr.NumberOfSymbols:04X}{Style.RESET_ALL}  ->  Number of syms")
    print(f"\t\t  {Fore.CYAN}{self.file_hdr.SizeOfOptionalHeader:04X}{Style.RESET_ALL}  ->  Size of opt header")
    print(f"\t\t  {Fore.CYAN}{self.file_hdr.Characteristics:04X}{Style.RESET_ALL}  ->  Characteristics")
    print("\t};")
  
  def parseOptHeader(self):
    print("\n\tstruct", Fore.MAGENTA + Style.DIM, "IMAGE_OPTIONAL_HEADER", Style.RESET_ALL, "{")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.Magic:04X}{Style.RESET_ALL}  ->  Magic")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.MajorLinkerVersion:04X}{Style.RESET_ALL}  ->  Major Linker Version")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.MinorLinkerVersion:04X}{Style.RESET_ALL}  ->  Minor Linker Version")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.SizeOfCode:04X}{Style.RESET_ALL}  ->  Size of code section")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.SizeOfInitializedData:04X}{Style.RESET_ALL}  ->  Size of initialized data")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.SizeOfUninitializedData:04X}{Style.RESET_ALL}  ->  Size of uninitialized data")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.AddressOfEntryPoint:04X}{Style.RESET_ALL} ->  Entry Point(RVA of startup code)")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.BaseOfCode:04X}{Style.RESET_ALL}  ->  Base RVA of code section")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.ImageBase:04X}{Style.RESET_ALL} -> Image base on memory")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.SectionAlignment:04X}{Style.RESET_ALL}  ->  Section alignment")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.FileAlignment:04X}{Style.RESET_ALL}  ->  File alignment")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.MajorOperatingSystemVersion:04X}{Style.RESET_ALL}  ->  Major Operating System Version")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.MinorOperatingSystemVersion:04X}{Style.RESET_ALL}  ->  Minor Operating System Version")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.SizeOfImage:04X}{Style.RESET_ALL} ->  Total size of image in memory")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.SizeOfHeaders:04X}{Style.RESET_ALL}  ->  Size of all PE headers")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.DllCharacteristics:04X}{Style.RESET_ALL}  -> DLL Characteristics")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.SizeOfStackReserve:04X}{Style.RESET_ALL} ->  Size of stack reserve")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.SizeOfStackCommit:04X}{Style.RESET_ALL}  ->  Size of stack commit")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.SizeOfHeapReserve:04X}{Style.RESET_ALL} ->  Size of heap reserve")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.SizeOfHeapCommit:04X}{Style.RESET_ALL}  ->  Size of heap commit")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.NumberOfRvaAndSizes:04X}{Style.RESET_ALL}  ->  Number of RVA and sizes")
    print("\t};")