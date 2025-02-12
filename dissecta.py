from plugins.master import Master
from plugins.yararuler import YaraRuler
from plugins.peparser import PEParser
from utils import banner
from colorama import Fore, Style
from argparse import ArgumentParser, RawTextHelpFormatter, ArgumentTypeError
import sys

try:
  import pefile
except:
  print(f"{Fore.RED + Style.DIM}[!]{Style.RESET_ALL} PEfile not installed or present in ./lib directory")
  sys.exit(1) 

def main():
  banner.get()
  parser = ArgumentParser(description="", formatter_class=RawTextHelpFormatter)
  
  parser.add_argument('-f', '--file', type=str, required=True, help='Select sample for analysis', metavar='')
  parser.add_argument('-a', '--author', type=str, required=False, help='YARA Rule Author', metavar='')
  parser.add_argument('-c', '--condition', type=str, default="any of them", help='YARA Rule condition (default: "any of them")', metavar='')
  parser.add_argument('--tags', nargs='+', default=[],required=False, help='Tags for dataset (ex: --tags Ransomware, Stealer)', metavar='')
  parser.add_argument('-d', '--dataset',action='store_true', required=False, help='Include report in dataset (Not required)')
  parser.add_argument('--infope', action='store_true', help='Obtain information from the PE Headers')
  args = parser.parse_args()
  
  if args.file:
    validatePE(args.file)
    master = Master(args.file, args.tags)
    master.reportJson()
    
    if args.author:
      ruler = YaraRuler(master, args.author, args.condition)
      ruler.writeRule()
      
    if args.dataset:
      master.datasetJson()
    
    if args.infope:
      peparser = PEParser(master)

def validatePE(file):
    DOS_HEADER = 0x5A4D  #MZ
    OPTIONAL_H_MAGIC = [0x10b, 0x20b] #PE32, PE32+
        
    try:
      pe = pefile.PE(file, fast_load=True)
      if pe.DOS_HEADER.e_magic != DOS_HEADER or pe.OPTIONAL_HEADER.Magic not in OPTIONAL_H_MAGIC:
          print(f"{Fore.RED + Style.DIM}[!]{Style.RESET_ALL} File not DOS HEADER or OPT HEADER")
          return False
      else:
          print(f"{Fore.MAGENTA}[{Fore.CYAN}+{Fore.MAGENTA}]{Style.RESET_ALL} DOS_HEADER -> {hex(DOS_HEADER)}\n{Fore.MAGENTA}[{Fore.CYAN}+{Fore.MAGENTA}]{Style.RESET_ALL} OPTIONAL_H_MAGIC -> {hex(pe.OPTIONAL_HEADER.Magic)}")
          ntSignature(pe)
    except Exception as e:
      print(f"{Fore.RED + Style.DIM}[!]{Style.RESET_ALL} An error has ocurred: {e}")
      
def ntSignature(file):
  try:
    signature = file.NT_HEADERS.Signature
    if signature == 0x5A4D:
        print(f"{Fore.MAGENTA}[{Fore.CYAN}+{Fore.MAGENTA}]{Style.RESET_ALL} NT SIGNATURE")
    elif signature == 0x454E:
        print(f"{Fore.MAGENTA}[{Fore.CYAN}+{Fore.MAGENTA}]{Style.RESET_ALL} NE SIGNATURE")
    elif signature == 0x4C45:
        print(f"{Fore.MAGENTA}[{Fore.CYAN}+{Fore.MAGENTA}]{Style.RESET_ALL} LE SIGNATURE")
    elif signature == 0x00004550:
        print(f"{Fore.MAGENTA}[{Fore.CYAN}+{Fore.MAGENTA}]{Style.RESET_ALL} PE00 SIGNATURE")
    else:
      print(f"{Fore.RED + Style.DIM}[!]{Style.RESET_ALL} UNKNOWN SIGNATURE")
      sys.exit(1)
  except Exception as e:
    print(f"{Fore.RED + Style.DIM}[!]{Style.RESET_ALL} An error has ocurred: {e}")

    
if __name__ == "__main__":
  main()