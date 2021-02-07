def translate(flag,goal="translate",check_bit=int):
    '''
    Translates the Flag attribute from win32_networkingloginprofile to human readable
    Usage:
        1.) Check if a bit is set: bit_mapper("513",goal="check",check_bit="1")
        2.) Turn flag into human readable: bit_mapper("513")
    '''
    bit_map_dic = {
        "0":"Script",
        "1":"Account Disabled",
        "3":"Home Dir Required",
        "4":"Lockout",
        "5":"Password Not Required",
        "6":"Password Can't Change",
        "7":"Encrypted Test Password Allowed",
        "8":"Temp Duplicate Account",
        "9":"Normal Account",
        "11":"InterDomain Trust Account",
        "12":"WorkStation Trust Account",
        "13":"Server Trust Account",
        "16":"Don't Expire Password",
        "17":"MNS Logon Account",
        "18":"Smartcard Required",
        "19":"Trusted For Delegation",
        "20":"Not Delegated",
        "21":"Use DES Key Only",
        "22":"Don't Require Preauthorization",
        "23":"Password Expired"
    }
    flag=int(flag)
    map="{0:b}".format(flag)
    if goal == "translate":
        temp = []
        for bit in enumerate(map):
            if bit[1] is "1":
                temp.append(str(bit_map_dic[str(bit[0])]))
        return temp
    elif goal == "check":
        for bit in enumerate(map):
            if bit[0] == int(check_bit) and bit[1] is "1":
                return True
        return False

def parse_json_message(hostname,record,chosen_subcategory,fields_wanted=["all"],filter={}):
    '''
    Function parses the message data returned from agents. Pass JSON instance from sqlalc to record variable.
    Ex. Database search: d=db.session.query(AgentId,AgentData).filter(AgentId.aid == AgentData.aid).all()
    Cont. parse_json_message(d,"win32_networkloginprofile",["Name","NumberOfLogons","BadPasswordCount","PrimaryGroupId"],{"filter on":"value"}):
    '''
    temp_list = []
    for agentdata in record:
        if agentdata.message["threathunt"] is not False: #// some records are false
            for ini_record in agentdata.message["threathunt"]:
                if chosen_subcategory in ini_record: #// get category selector
                    for category,catdata in ini_record.items():
                        for subdata in catdata:
                            #// Filter on specific fields in the JSON fields 
                            if filter.viewitems() <= subdata.viewitems():
                                temp_json = {}
                                for key,value in subdata.items(): #// for each ini record
                                    if fields_wanted and fields_wanted[0] == "all": #// return all fields in output
                                        temp_json[key] = value
                                    else:
                                        if key in fields_wanted: #// specific fields wanted in the output
                                            temp_json[key] = value
                                temp_json["agent_hostname"] = hostname #// add the hostname of agent where the data came from
                                temp_json["data_gathered"] = str(agentdata.date_added) #// add the hostname of agent where the data came from
                                if temp_json:
                                    temp_list.append(json.dumps(temp_json))
    return temp_list
