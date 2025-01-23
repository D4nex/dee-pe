from lib.analysis import Analyzer
from lib.master import Master
from lib.yararuler import YaraRuler
from utils import banner
from colorama import Fore, Style
from argparse import ArgumentParser, RawTextHelpFormatter, ArgumentTypeError

try:
  import pefile
except:
  print(f"{Fore.RED + Style.DIM}[!]{Style.RESET_ALL} PEfile not installed or present in ./lib directory")
  sys.exit(1) 

def main():
  banner.get()
  parser = ArgumentParser(description="", formatter_class=RawTextHelpFormatter)
  
  parser.add_argument('-f', '--file', type=str, required=True, help='Select sample for analysis', metavar='')
  parser.add_argument('-a', '--author', type=str, required=True, help='YARA Rule Author', metavar='')
  parser.add_argument('-c', '--condition', type=str, default="any of them", help='YARA Rule condition (default: "any of them")', metavar='')
  parser.add_argument('--tags', nargs='+', default=[],required=True, help='Tags for dataset (ex: --tags Ransomware, Stealer)', metavar='')
  parser.add_argument('-d', '--dataset',action='store_true', required=False, help='Include report in dataset (Not required)')
  args = parser.parse_args()
  
  if args.file and args.tags:
    validatePE(args.file)
    master = Master(args.file, args.tags)
    ruler = YaraRuler(master, args.author, args.condition)
    
    master.reportJson()
    ruler.writeRule()
    
    if args.dataset:
      master.datasetJson()
      
def validatePE(file):
    DOS_HEADER = 0x5A4D  #MZ
    NT_H_SIGN = 0x00004550 #PE\0\0
    OPTIONAL_H_MAGIC = [0x10b, 0x20b] #PE32, PE32+
        
    pe = pefile.PE(file, fast_load=True)
    try:
      if pe.DOS_HEADER.e_magic != DOS_HEADER or pe.NT_HEADERS.Signature != NT_H_SIGN or pe.OPTIONAL_HEADER.Magic not in OPTIONAL_H_MAGIC:
          print(f"{Fore.RED + Style.DIM}[!]{Style.RESET_ALL} File not DOS HEADER or OPT HEADER/Not PE")
          return False
      else:
          print(f"{Fore.MAGENTA}[{Fore.CYAN}+{Fore.MAGENTA}]{Style.RESET_ALL} DOS_HEADER -> {hex(DOS_HEADER)}\n{Fore.MAGENTA}[{Fore.CYAN}+{Fore.MAGENTA}]{Style.RESET_ALL} OPTIONAL_H_MAGIC -> {hex(pe.OPTIONAL_HEADER.Magic)}")
    except Exception as e:
      print(f"{Fore.RED + Style.DIM}[!]{Style.RESET_ALL} An error has ocurred: {e}")
    
if __name__ == "__main__":
  main()