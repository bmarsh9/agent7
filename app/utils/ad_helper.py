from app.models import *
from app.utils.operations import ADOps
#from app.utils.misc import spn_desc
from app import db
import ast
from sqlalchemy import func
from datetime import datetime
import arrow
import bisect

class ADHelper():
    def __init__(self):
        pass

    def get_users(self,user=None):
        q = db.session.query(ADUser)
        if user:
            q = q.filter(ADUser.name == user)
        return q.all()

    def get_computers(self,computer=None):
        q = db.session.query(ADComputer)
        if computer:
            q = q.filter(ADComputer.name == computer)
        return q.all()

    def get_groups(self,group=None):
        q = db.session.query(ADGroup)
        if group:
            q = q.filter(ADGroup.name == group)
        return q.all()

    def get_active_users(self,days=60):
        dataset = []
        for user in self.get_users():
            if self.get_last_logon(user.lastlogon) <= days:
                dataset.append(user)
        return dataset

    def get_active_computers(self,days=60):
        dataset = []
        for computer in self.get_computers():
            if self.get_last_logon(computer.lastlogon) <= days:
                dataset.append(computer)
        return dataset

    def get_empty_groups(self):
        return ADGroup.query.filter(ADGroup.members_count == 0).all()

    def get_assets_in_group(self,group):
        dataset = []
        seen = []
        members_of_group = ADOps().members(group,tree=False)
        if members_of_group:
            for member in members_of_group:
                name = member["name"].lower()
                if name not in seen:
                    seen.append(name)
                    dataset.append({"name":member["name"],"objectclass":member["meta"]["object"]})
        return dataset

    def get_users_in_group(self,group):
        dataset = []
        assets = self.get_assets_in_group(group)
        if assets:
            for asset in assets:
                if asset["objectclass"] == "user":
                    dataset.append(asset["name"].lower())
        return dataset

    def get_groups_in_group(self,group):
        dataset = []
        assets = self.get_assets_in_group(group)
        if assets:
            for asset in assets:
                if asset["objectclass"] == "group":
                    dataset.append(asset["name"].lower())
        return dataset

    def get_computers_in_group(self,group):
        dataset = []
        assets = self.get_assets_in_group(group)
        if assets:
            for asset in assets:
                if asset["objectclass"] == "computer":
                    dataset.append(asset["name"].lower())
        return dataset

    def get_privileged_groups(self):
        return AssetLedger.query.filter(AssetLedger.objectclass == "group").all()

    def get_users_in_privileged_groups(self):
        dataset = []
        users_in_ledger = AssetLedger.query.filter(AssetLedger.objectclass == "user").all()
        assets = self.get_assets_in_privileged_groups()
        if assets:
            for asset in assets:
                if asset["objectclass"] == "user":
                    dataset.append(asset["name"].lower())
            for user in users_in_ledger:
                search = "%{}%".format(user.name)
                obj_user = ADUser.query.filter(ADUser.name.like(search)).first()
                if obj_user:
                    if obj_user.name not in dataset:
                        dataset.append(obj_user.name)
        return dataset

    def get_priv_users(self):
        dataset = []
        users = self.get_users_in_privileged_groups()

        for enum,user in enumerate(users,1):
            user_obj = ADUser.query.filter(func.lower(ADUser.name) == user).first()
            if user_obj:
                dataset.append(user_obj)
        return dataset

    def get_groups_in_privileged_groups(self):
        dataset = []
        assets = self.get_assets_in_privileged_groups()
        if assets:
            for asset in assets:
                if asset["objectclass"] == "group":
                    dataset.append(asset["name"].lower())
        return dataset

    def get_computers_in_privileged_groups(self):
        dataset = []
        assets = self.get_assets_in_privileged_groups()
        if assets:
            for asset in assets:
                if asset["objectclass"] == "computer":
                    dataset.append(asset["name"].lower())
        return dataset

    def get_assets_in_privileged_groups(self):
        dataset = []
        seen = []
        groups = self.get_privileged_groups()
        for group in groups:
            members_of_group = ADOps().members(group.name,tree=False,startswith=True)
            if members_of_group:
                for member in members_of_group:
                    name = member["name"].lower()
                    if name not in seen:
                        seen.append(name)
                        dataset.append({"name":member["name"],"objectclass":member["meta"]["object"]})
        return dataset

    def get_users_in_privileged_groups_by_group(self,include_members=True):
#haaaaaaa
        dataset = []
        groups = self.get_privileged_groups()
        for group in groups:
            members_of_group = ADOps().members(group.name,tree=False,startswith=True)
            if members_of_group:
                seen = []
                temp = {"group":group.name,"managed":0,"unmanaged":0,"total":0}
                if include_members:
                    temp["user_members"] = []
                for member in members_of_group:
                    name = member["name"].lower()
                    if member["meta"]["object"] == "user":
                        if name not in seen:
                            seen.append(name)
                            if include_members:
                                temp["user_members"].append(name)
                            u = ADUser.query.filter(ADUser.name == name).order_by(ADUser.id.desc()).first()
                            if u:
                                if u.managed:
                                    temp["managed"] += 1
                                else:
                                    temp["unmanaged"] += 1
                                temp["total"] += 1
                dataset.append(temp)
        return dataset

    def group_has_user(self,group,name):
        if name.lower() in self.get_users_in_group(group):
            return True
        return False

    def group_has_group(self,group,name):
        if name.lower() in self.get_groups_in_group(group):
            return True
        return False

    def group_has_computer(self,group,name):
        if name.lower() in self.get_computers_in_group(group):
            return True
        return False

    def user_in_priv_group(self,name):
        for user in self.get_users_in_privileged_groups():
            if name.lower() in user:
                return True
        return False

    def computer_in_priv_group(self,name):
        if name.lower() in self.get_computers_in_privileged_groups():
            return True
        return False

    def group_in_priv_group(self,name):
        if name.lower() in self.get_groups_in_privileged_groups():
            return True
        return False

    def get_spn_from_str(self,str_spn,only_service=False,as_dict=False):
        '''
        usage: ADHelper().get_spn_from_str(user.serviceprincipalname,only_service=True)
        str_spn = "('mssql/host.example.com', 'HTTP/webserver')"
        '''
        services = []
        seen = []
        try:
            formatted = ast.literal_eval(str_spn)
        except:
            formatted = [str_spn]

        for enum,service in enumerate(formatted):
            service = service.lower()
            if only_service:
                service = service.split("/")[0]
            if service not in seen: #no duplicates
                seen.append(service)
                if as_dict:
                    services.append({enum:service})
                else:
                    services.append(service)
        return services

    def has_spn(self,str_spn,service):
        full_services = self.get_spn_from_str(str_spn,only_service=True)
        if service.lower() in full_services:
            return True
        return False

    def hosts_with_spn(self,service):
        data = []
        format = "%{}%".format(service)
        # this will also grab computer accounts b/c we are not filtering on objectclass attr
        users = ADUser.query.filter(ADUser.serviceprincipalname.ilike(format)).distinct(ADUser.objectsid).all()
        if users:
            data = users
        return data

    def get_all_spn(self,distinct=True):
        non_distinct = {}

        user_list = []
        computer_list = []
        users=ADUser.query.filter(ADUser.serviceprincipalname!=None).all()
        for user in users:
            for spn in self.get_spn_from_str(user.serviceprincipalname,only_service=True):
                if distinct:
                    if spn not in user_list:
                        user_list.append(spn)
                else:
                    if spn not in non_distinct:
                        non_distinct[spn] = 1
                    else:
                        non_distinct[spn] += 1
        '''
        computers=ADComputer.query.filter(ADComputer.serviceprincipalname!=None).all()
        for computer in computers:
            for spn in self.get_spn_from_str(computer.serviceprincipalname,only_service=True):
                if distinct:
                    if spn not in computer_list:
                        computer_list.append(spn)
                else:
                    if spn not in non_distinct:
                        non_distinct[spn] = 1
                    else:
                        non_distinct[spn] += 1
        '''
        if not distinct:
            return non_distinct
        resulting_list = list(user_list)
        #resulting_list.extend(x for x in computer_list if x not in resulting_list)
        return resulting_list

    def get_all_spn_metrics(self):
        data = []
        spn = self.get_all_spn(distinct=False)
        for service,count in spn.items():
            data.append({"service":service,"count":count,"description":self.spn_desc(service)})
        return data

    def get_priv_users_format_1(self):
        dataset = []
        users = self.get_users_in_privileged_groups()

        for enum,user in enumerate(users,1):
            user_obj = ADUser.query.filter(func.lower(ADUser.name) == user).first()
            if user_obj:
                if not user_obj.lastlogon:
                    lastlogon = 0
                temp = {
                    "id":enum,
                    "sid":user_obj.objectsid,
                    "cn":user_obj.name,
                    "distinguishedname":user_obj.distinguishedname,
                    "lastlogon":str(user_obj.lastlogon),
                    "logoncount":user_obj.logoncount or 0,
                    "service_account":"no",
                    "roastable":"no",
                    "non_exp_password":"no",
                    "disabled":"no",
                    "delegation":"no",
                    "account_is_sensitive":"no",
                    "active":"no",
                    "require_preauth":"yes",
                    "password_encrypted":"yes",
                    "smartcard_required":"no",
                    "des_key_only":"no",
                }

                if user_obj.serviceprincipalname:
                    temp["service_account"] = "yes"
                    temp["roastable"] = "yes"
                if "DONT_EXPIRE_PASSWD" in user_obj.useraccountcontrol:
                    temp["non_exp_password"] = "yes"
                if "ACCOUNTDISABLE" in user_obj.useraccountcontrol:
                    temp["disabled"] = "yes"
                if "FOR_DELEGATION" in user_obj.useraccountcontrol:
                    temp["delegation"] = "yes"
                if "NOT_DELEGATED" in user_obj.useraccountcontrol:
                    temp["account_is_sensitive"] = "yes"
                if "DONT_REQUIRE_PREAUTH" in user_obj.useraccountcontrol:
                    temp["require_preauth"] = "no"
                if "ENCRYPTED" in user_obj.useraccountcontrol:
                    temp["password_encrypted"] = "no"
                if "SMARTCARD" in user_obj.useraccountcontrol:
                    temp["smartcard_required"] = "yes"
                if "DES_KEY" in user_obj.useraccountcontrol:
                    temp["des_key_only"] = "yes"

                # calculate amount of days since last pwd change and logon
                temp["last_pwd_change"] = self.get_days_since_last_pwd_change(user_obj.pwdlastset)
                days_since_logon = self.get_last_logon(user_obj.lastlogon)
                temp["last_logon"] = days_since_logon
                if days_since_logon <= 60:
                    temp["active"] = "yes"
                dataset.append(temp)
        return dataset

    def password_last_changed_buckets(self,bucket_size=180,bucket_length=20):
        '''get domain user accounts and the password last changed and group in buckets'''
        data = {}
        users = self.get_users()
        if users:
            intervals = [0] + [x * bucket_size for x in range(1, bucket_length)]
            for user in users:
                try:
                    bucket = intervals[bisect.bisect_left(intervals, self.get_days_since_last_pwd_change(user.pwdlastset))]
                    if bucket <= 0:
                        bucket_label = "0"
                    else:
                        bucket_label = "{}-{}".format(bucket-bucket_size,bucket)
                except IndexError: # place in last bucket
                    bucket = intervals[-1]
                    bucket_label = "{}+".format(bucket)

                if bucket_label in data:
                    data[bucket_label] += 1
                else:
                    data[bucket_label] = 1
        return data

    def password_last_changed_buckets_ex(self,bucket_size=180,bucket_length=20):
        '''get all user accounts and the password last changed and group in buckets'''
        data = {}
        domain_users = self.get_users()
        local_users = AgentUser.query.all()
        users = domain_users + local_users
        if users:
            intervals = [0] + [x * bucket_size for x in range(1, bucket_length)]
            for user in users:
                if hasattr(user,"pwdlastset"):
                    pwd = self.get_days_since_last_pwd_change(user.pwdlastset)
                else:
                    pwd = self.get_days_since_last_pwd_change(user.last_password_change)
                try:
                    bucket = intervals[bisect.bisect_left(intervals, pwd)]
                    if bucket <= 0:
                        bucket_label = "0"
                    else:
                        bucket_label = "{}-{}".format(bucket-bucket_size,bucket)
                except IndexError: # place in last bucket
                    bucket = intervals[-1]
                    bucket_label = "{}+".format(bucket)

                if bucket_label in data:
                    data[bucket_label] += 1  
                else:
                    data[bucket_label] = 1
        return data   


    def get_last_logon(self,lastlogon):
        now = arrow.get(datetime.now())
        last_logon = arrow.get(lastlogon)
        delta = (now-last_logon)
        return delta.days

    def get_days_since_last_pwd_change(self,lastset):
        now = arrow.get(datetime.now())
        pwd_change = arrow.get(lastset)
        delta = (now-pwd_change)
        return delta.days


    def spn_desc(self,spn):
        spn_map = {
        "mssql":"Microsoft SQL Server", 
        "kadmin":"Kerberos",
        "wsman":"Windows Remote Management (based on WS-Management standard) service",
        "termsrv":"Microsoft Remote Desktop Protocol Services, aka Terminal Services",
        "ldap":"LDAP service such as on a Domain Controller or ADAM instance.",
        "gc":"Domain Controller Global Catalog services",
        "restrictedkrbhost":"The class of services that use SPNs with the serviceclass string equal to 'RestrictedKrbHost', whose service tickets use the computer account’s key and share a session key",
        "dns":"Domain Name Server",
        "ftp":"File Transfer Protocol", 
        "hdfs":"hadoop",
        "hive":"hadoop metastore",
        "host":"The HOST service represents the host computer. The HOST SPN is used to access the host computer account whose long term key is used by the Kerberos protocol when it creates a service ticket.",
        "http":"SPN for http web services that support Kerberos authentication",
        "httpfs":"Hadoop HDFS over HTTP",
        "https":"SPN for http web services that support Kerberos authentication",
        "imap":"Internet Message Access Protocol",
        "imap4":"Internet Message Access Protocol version 4",
        "kafka":"Apache Kafka",
        "mongod":"MongoDB Enterprise",  
        "nfs":"Network File System",
        "rpc":"Remote Procedure Call",
        "smtp":"Simple Mail Transfer Protocol",
        "tapinego":"Associated with routing applications such as Microsoft firewalls (ISA, TMG, etc)",
        "vnc":"VNC Server",
        "vpn":"Virtual Private Network",
        "yarn":"Hadoop NodeManager",
        "cifs":"Common Internet File System",
        "ipp":"Internet Printing Protocol",
        }
        return spn_map.get(spn.lower())

