from app.models import IpLocation,AuditKeyLedger,AgentAuditKey,AgentUser,ADUser,Agent
from sqlalchemy import func
import ipaddress
from app.utils.db_helper import DynamicQuery
from app.utils.ad_helper import ADHelper

def lookup_ip(address):
    try:
        if ipaddress.ip_address(address).is_global:
            address_dec = int(ipaddress.ip_address(address))
            query = IpLocation.query.filter(IpLocation.ip_to > address_dec).filter(IpLocation.ip_from < address_dec).first()
            return query
        else:
            return None
    except:
        return None

def color_scheme(id=None):
#    color_dict = {1: '#898ad4', 2: '#88a571', 3: '#a0af51', 4: '#bdb739', 5: '#ddbd24', 6: '#faa825', 7: '#f38f32', 8: '#ec753b', 9: '#e45841', 10: '#dc3545'} #lightest
    color_dict = {1: '#898ad4', 2: '#80a997', 3: '#99ba7b', 4: '#b8c866', 5: '#dbd551', 6: '#ffd242', 7: '#ffa82e', 8: '#ff781a', 9: '#f34508', 10: '#d90000'}
#    color_dict = {1: '#7bcb7d', 2: '#87b970', 3: '#90a764', 4: '#979558', 5: '#9b834c', 6: '#9d7141', 7: '#9e5e36', 8: '#9e492c', 9: '#9c3122', 10: '#990718'} #darker
    if id:
        return color_dict.get(id,1)
    return color_dict

def enrich_auditkey(keys=[{}]):
    '''
    keys = [{"key":"full\\path\\to\\registry\\key","value":1}]
    '''
    data={}
    key_data = []
    total = 0
    compliant = 0
    non_compliant = 0
    for key in keys:
        ledger = AuditKeyLedger.query.filter(func.lower(AuditKeyLedger.full_path) == key["key"].lower()).first()
        if ledger:
            temp = {"key":key["key"],"value":key["value"],"host_name":key["host_name"],"compliant_value":ledger.value,"title":ledger.title,"severity":ledger.severity,"compliant":"no"}
            if ledger.value != str(key["value"]):
                non_compliant += 1
            else:
                temp["compliant"] = "yes"
                compliant += 1
            total += 1
            key_data.append(temp)
    percentage_compliant = round(compliant/total*100)
    if percentage_compliant >= 90:
        grade = "A"
    elif percentage_compliant >= 80:
        grade = "B"
    elif percentage_compliant >= 70:
        grade = "C"
    elif percentage_compliant >= 60:
        grade = "D"
    elif percentage_compliant >= 50:
        grade = "E"
    else:
        grade = "F"

    data["total"] = total
    data["compliant"] = compliant
    data["non_compliant"] = non_compliant
    data["percentage_compliant"] = percentage_compliant
    data["grade"] = grade
    data["results"] = key_data

    return data
