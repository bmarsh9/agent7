from .dictionary import Dictionary
import hashlib
import json

class DedupCreator():
    def __init__(self):
        pass

    def create_message_id(self,model,record,doc_hash=None):
        '''
        if not isinstance(record,dict):
            print("Invalid format. Its likely that the record is not properly nested.")
            return None,doc_hash
        '''

        if doc_hash:
            doc_hash = hashlib.sha1(json.dumps(record, sort_keys=True).encode()).hexdigest()
        fields = Dictionary(model).get_fields()
        if fields:
            sha1 = hashlib.sha1()
            for field in fields:
                val = record.get(field)
                if val:
                    val = str(val).encode('utf-8')
                    sha1.update(val)
            return sha1.hexdigest(),doc_hash
        return None,doc_hash
