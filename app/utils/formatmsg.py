import json

def msg_to_json(message="None",result=False,label="warning",**kwargs):
    '''
    .Description --> Return JSON message for the result
    '''
    message = {
        "message":str(message),
        "result":result,
        "type":str(label),
        "id":kwargs.get("id")
    }
    return message
