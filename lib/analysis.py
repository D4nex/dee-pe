from lib.modules.metadata import Metadata
from lib.modules.hashes import Hashes
from lib.modules.strings import Strings
from lib.modules.sections import Sections
from lib.modules.winapi import WinApi
from lib.modules.libraries import Imports

class Analyzer:
    def __init__(self, file, debug_mode=False, blobs=None):
        if blobs is None:
            blobs = []
        if debug_mode == True:
            self.entry_point = ""
            self.opcodes = {}
        self.file = file
        self.metadata = {}
        self.hashes = {}
        self.strings = {}
        self.urls = {}
        self.sections = {}
        self.winapi = {}
        self.dlls = {}
        self.imphash = None

    def Parse(self):
        newMetadata = Metadata.parse(self.file)
        newHashes = Hashes.parse(self.file)
        newStrings = Strings.parse(self.file)
        newSections = Sections.parse(self.file)
        newCalls = WinApi.parse(self.file)
        newDlls = Imports.parse(self.file)
        
        self.metadata = newMetadata.to_dict()
        self.hashes = newHashes.to_dict()
        self.strings = newStrings.strings
        self.urls = newStrings.urls
        self.sections = newSections.info
        self.opcodes = newSections.opcodes
        self.winapi = newCalls.calls
        self.dlls = newDlls.dlls
        self.imphash = newDlls.imphash