<p align="center">
    <img src="https://github.com/user-attachments/assets/c05d24d7-960e-47e2-9af5-8716ca375c11" alt="Dee-PE logo">
</p>

<h3 align="center">Dee-PE</h3>
<p align="center">
    A simple <i>dissectool</i> to play and have fun statically with little <i>malware</i>. Only <b>PE/PE32+</b> format
</p>

##Install
```
git clone https://github.com/D4nex/dee-pe
cd dee-pe
pip install -r requirements.txt
python3 main.py -h
```

## Short description
```
  _           _   _
 | \  _   _  |_) |_
 |_/ (/_ (/_ |   |_
                    > Now dissect that malware like a insect =^-^ =

usage: main.py [-h] -f  -a  [-c] --tags  [...] [-d]

options:
  -h, --help         show this help message and exit
  -f , --file        Select sample for analysis
  -a , --author      YARA Rule Author
  -c , --condition   YARA Rule condition (default: "any of them")
  --tags  [ ...]     Tags for dataset (ex: --tags Ransomware, Stealer)
  -d, --dataset      Include report in dataset (Not required)
```

### Reports

Generates a report in JSON format with the file in pieces (all possible IOCs).

**INCLUDES**:
- Metadata - (Name, File Size, Time Stamp, Machine, Others)
- Hashes - (md5, sha1, sha256)
- Readable strings
- URLs
- Sections - (V_Addr, V_Size, Data Size, Perms, Entropy)
- Imphash
- Executable sections opcodes
- WINDOWS API calls
- Imports

> PATH: ./reports/*.deep

### YARA Rules

Generate a YARA rule based on the possible IOCs in the program (must be for better accuracy e.g. inserting strings, or more data extracted).
> PATH: ./yara-rules/*.yar

### Dataset
Insert data into a dataset for future training of an ML model (to avoid data congestion avoid using the -d parameter if you are not sure about inserting it into the dataset).
> PATH: ./dataset/dataset.json

## Known Issues

- **Comment the code**: I know, only 5 minutes
- **VirusTotal Integration**: Integration with Virus Total for file scanning
- Mmmm...little things
