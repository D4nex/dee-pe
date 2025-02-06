from lib.analysis import Analyzer
from datetime import datetime
import os, json, re
from colorama import Fore, Style

class Master:
  def __init__(self, file, tags: []):
    self.file = file
    self.tags = tags
    self.analysis = Analyzer(file, debug_mode=True)
    self.date = datetime.now().strftime("%Y-%m-%d")
    self.analysis.Parse()
    
  def reportJson(self):
    path = "reports"
    file = f"{self.date}_{self.analysis.hashes['md5']}_REPORT.deep"
    
    if not os.path.exists(path):
      os.makedirs(path)
    output_file = os.path.join(path, file)
    
    data = {}
    
    report_index = f"{self.date}_{self.file}_REPORT"
    report = {
      "metadata": self.analysis.metadata,
      "hashes": self.analysis.hashes, 
      "strings": self.analysis.strings, 
      "urls": self.analysis.urls, 
      "sections": self.analysis.sections, 
      "imphash": self.analysis.imphash, 
      "opcodes": self.analysis.opcodes, 
      "api_calls": self.analysis.winapi, 
      "imports": self.analysis.dlls
    }
    data[report_index] = report
    try:
      with open(output_file, "w") as json_file:
        json.dump(data, json_file, indent=4)
      print(f"{Fore.MAGENTA}[{Fore.CYAN}+{Fore.MAGENTA}]{Style.RESET_ALL} Report saved to {output_file}!")
    except Exception as e:
      print(f"{Fore.RED + Style.DIM}[!]{Style.RESET_ALL} An error has ocurred: {e}")
    
  def datasetJson(self):
    name = self.analysis.metadata['Name']
    time_stamp = self.analysis.metadata['Time Stamp']
    machine = self.analysis.metadata['Machine']
    characteristics = self.analysis.metadata['Characteristics']
    hashes = []
    imphash = self.analysis.imphash
    opcodes = []
    strings = []
    urls = []
    api_calls = []
    imports = []
    tags = self.tags
    path = "dataset"
    file = "dataset.json"
    output_file = os.path.join(path, file)
    try:
      for key, hash_value in self.analysis.hashes.items():
        hashes.append(hash_value)
      for key, opcode in self.analysis.opcodes.items():
        for key, op in opcode.items():
          opcodes.append(op)
      for index, string in self.analysis.strings.items():
        strings.append(string)
      r_strings = [
      s for s in strings
      if re.match(r'^[A-Za-z0-9\s\.,;:\'\"\-\!\(\)\{\}\[\]]+$', s)
      ]
      for index, url in self.analysis.urls.items():
        urls.append(url)
      for index, call in self.analysis.winapi.items():
        api_calls.append(call)
      for dll in self.analysis.dlls:
        imports.append(dll)
        
      sample = {
        "Name": name,
        "Time stamp": time_stamp,
        "Machine": machine,
        "Characteristics": characteristics,
        "Hashes": hashes,
        "Imphash": imphash,
        "Opcodes": opcodes,
        "Strings": r_strings,
        "Urls": urls,
        "Api Calls": api_calls,
        "Imports": imports,
        "Tags": tags
      }
      if os.path.exists(output_file):
        with open(output_file, 'r') as f:
          data = json.load(f)
      else:
        os.makedirs(path)
        data = {"Samples": []}
        
      data["Samples"].append(sample)
      with open(output_file, 'w') as f:
        json.dump(data, f, indent=4)
      print(f"{Fore.MAGENTA}[{Fore.CYAN}+{Fore.MAGENTA}]{Style.RESET_ALL} Add sample to {output_file}")
    except Exception as e:
      print(f"{Fore.RED + Style.DIM}[!]{Style.RESET_ALL} An error has ocurred: ", e)