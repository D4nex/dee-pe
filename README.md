<p align="center">
    <img src="assets/dissecta.png" alt="Dissecta logo">
</p>

<p align="center">
    A simple <i>dissectool</i> to play and have fun statically with little <i>malware</i>. Only <b>PE/PE32+</b> format
</p>

## About the project

![DissectaHelp](assets/help.jpg)

Dissecta happens to be a tool created in the context of my learning about malware analysis. It pretends to be a facility for the static analysis of PE files, taking it as an object to dissect (understand the reference malware -> biological virus) their `PE structure` and generating a report of it for further analysis or integration with other tools. It also has an integrated plugin system (explained in the [official Doc](doc/README.md)) that allows the scalability of the project.

### Reports

Generates a report in `.dsx`(JSON) format with the possible features(IOCS in any case)

**Features**:
- `Metadata` - (Name, File Size, Time Stamp, Machine, Others)
- `Hash Sum` - (md5, sha1, sha256)
- `Readable strings`
- `URLs`
- `Sections` - (Virtual Addr, Virtual Size, Data Size, Perms, Entropy)
- `Imphash`
- `Executable sections opcodes`
- `WINDOWS API calls`
- `Imports`

> PATH: ./reports/*.dsx

### Dataset
Insert features into a dataset for future training of an ML model (to avoid data congestion avoid using the -d parameter if you are not sure about inserting it into the dataset).
> PATH: ./dataset/dataset.json

## Acknowledgements

- [Bible Malcore](https://bible.malcore.io/) - *For its intuitive and well explained section: "Windows PE File Structure".*
  
- [PEfile Project](https://github.com/erocarrera/pefile) - *For the library used in this project that made things easier for me.*

Thanks.

