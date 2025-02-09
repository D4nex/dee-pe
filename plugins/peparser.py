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
    print(f"\n\t\t{Fore.MAGENTA}========================={Style.RESET_ALL}\n \t\t   IMAGE_DOS_HEADER \n\t\t{Fore.MAGENTA}========================={Style.RESET_ALL}")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_magic:04X}{Style.RESET_ALL}  ->  Magic Number")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_cblp:04X}{Style.RESET_ALL}  ->  Bytes on last page of file")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_cp:04X}{Style.RESET_ALL}  ->  Pages in file")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_crlc:04X}{Style.RESET_ALL}  ->  Relocations")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_cparhdr:04X}{Style.RESET_ALL}  ->  Size of header")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_minalloc:04X}{Style.RESET_ALL}  ->  Minimum extra paragraphs needed")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_maxalloc:04X}{Style.RESET_ALL}  ->  Maximum extra paragraphs needed")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_ss:04X}{Style.RESET_ALL}  ->  Initial SS value")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_sp:04X}{Style.RESET_ALL}  ->  Initial SP value")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_csum:04X}{Style.RESET_ALL}  ->  Checksum")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_ip:04X}{Style.RESET_ALL}  ->  Initial IP value")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_cs:04X}{Style.RESET_ALL}  ->  Initial CS value")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_lfarlc:04X}{Style.RESET_ALL}  ->  File addr of rtable")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_ovno:04X}{Style.RESET_ALL}  ->  Overlay number")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_oemid:04X}{Style.RESET_ALL}  ->  OEM identifier")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_oeminfo:04X}{Style.RESET_ALL}  ->  OEM information")
    print(f"\t\t  {Fore.CYAN}{self.dos_hdr.e_lfanew:04X}{Style.RESET_ALL}  ->  File addr of new exe header")
  
  def parseFileHdr(self):
    print(f"\n\t\t{Fore.MAGENTA}========================={Style.RESET_ALL}\n \t\t   IMAGE_FILE_HEADER \n\t\t{Fore.MAGENTA}========================={Style.RESET_ALL}")
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
  
  def parseOptHeader(self):
    print(f"\n\t\t{Fore.MAGENTA}========================={Style.RESET_ALL}\n \t\t   IMAGE_OPTIONAL_HEADER\n\t\t{Fore.MAGENTA}========================={Style.RESET_ALL}")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.Magic:04X}{Style.RESET_ALL}  ->  Magic")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.MajorLinkerVersion:04X}{Style.RESET_ALL}  ->  Major Linker Version")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.MinorLinkerVersion:04X}{Style.RESET_ALL}  ->  Minor Linker Version")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.SizeOfCode:04X}{Style.RESET_ALL}  ->  Size of code")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.SizeOfInitializedData:04X}{Style.RESET_ALL}  ->  Size of initialized data")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.SizeOfUninitializedData:04X}{Style.RESET_ALL}  ->  Size of uninitialized data")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.AddressOfEntryPoint:04X}{Style.RESET_ALL} ->  Address of entry point")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.BaseOfCode:04X}{Style.RESET_ALL}  ->  Base of Code")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.ImageBase:04X}{Style.RESET_ALL} -> Image Base")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.SectionAlignment:04X}{Style.RESET_ALL}  ->  Section Alignment")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.FileAlignment:04X}{Style.RESET_ALL}  ->  File Alignment")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.MajorOperatingSystemVersion:04X}{Style.RESET_ALL}  ->  Major Operating System Version")
    print(f"\t\t  {Fore.CYAN}{self.opt_hdr.MinorOperatingSystemVersion:04X}{Style.RESET_ALL}  ->  Minor Operating System Version")
    