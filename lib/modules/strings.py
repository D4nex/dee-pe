import re

class Strings:
        def __init__(self):
            self.length = 10
            self.url_pattern = b'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            self.strings = {}
            self.urls = {}
        @staticmethod
        def parse(file):
            instance = Strings()
            
            with open(file, 'rb') as f:
                data = f.read()
                strings = re.findall(rb'[\x20-\x7E]{' + str(instance.length).encode() + rb',}', data)
                for index, string in enumerate(strings):
                    instance.strings[index] = string.decode('utf-8', errors='ignore')
                urls = re.findall(instance.url_pattern, data)
                for index, url in enumerate(urls):
                    instance.urls[index] = string.decode('utf-8', errors='ignore')
            return instance
            
            
            
