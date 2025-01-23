import hashlib

class Hashes:
        def __init__(self):
            self.md5 = None
            self.sha1 = None
            self.sha256 = None
            
        def to_dict(self):
            return {
                "md5": self.md5,
                "sha1": self.sha1,
                "sha256": self.sha256
                }
        @staticmethod
        def parse(file):
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            
            instance = Hashes()
            with open(file, "rb") as f:
                while True:
                    data = f.read()
                    if not data:
                        break
                    instance.md5 = md5.update(data)
                    instance.sha1 = sha1.update(data)
                    instance.sha256 = sha256.update(data)
            f.close()
            instance.md5 = md5.hexdigest()
            instance.sha1 = sha1.hexdigest()
            instance.sha256 = sha256.hexdigest()
            return instance
                    
                    
            