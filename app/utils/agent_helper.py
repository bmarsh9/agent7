from app.models import Agent,AgentUser,ADUser,AgentLogon
from app import db
import ast
from sqlalchemy import func
from datetime import datetime
import arrow
import bisect
from app.utils.db_helper import DynamicQuery

class AgentHelper():
    def __init__(self):
        pass

    def get_users(self,user=None):
        q = db.session.query(AgentUser)
        if user:
            q = q.filter(AgentUser.name == user)
        return q.all()

    def get_privileged_users(self):
        # get all local privileged users
        local_accounts = AgentUser.query.filter(AgentUser.local_account == True).filter(AgentUser.priv == 2).order_by(AgentUser.date_added.desc()).all()
        # remove accounts that are on hosts uninstalled
        return local_accounts

    def get_count_of_service_dependencies_for_username_on_host(self,username,host):
        agent = Agent.query.filter(Agent.hostname == host).first()
        services = AgentService.query.filter(AgentService.username == username).filter(AgentService.host_id == agent.id).all()
        pass

    def password_last_changed_buckets(self,bucket_size=180,bucket_length=20):
        '''get domain user accounts and the password last changed and group in buckets'''
        data = {}
        users = self.get_users()
        if users:
            intervals = [0] + [x * bucket_size for x in range(1, bucket_length)]
            for user in users:
                try:
                    bucket = intervals[bisect.bisect_left(intervals, self.get_days_since_last_pwd_change(user.last_password_change))]
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

    def get_days_since_last_pwd_change(self,lastset):
        now = arrow.get(datetime.now())
        pwd_change = arrow.get(lastset)
        delta = (now-pwd_change)
        return delta.days


    # Host logon map
    def get_logon_map_for_host(self,id):
        nodes = []
        edges = []
        a = Agent.query.get(id)
        if a:
            label = "{}".format(a.hostname)
            meta = {"hostname":a.hostname,"os":a.edition,"domain_joined":str(a.domain_joined),"host_id":a.id,"domain":a.domain}
#haaaaa
            if a.installtype.lower() in ("server"):
                meta["type"] = "server"
                nodes.append({"id":1,"image":"/static/assets/img/server_icon_4.png","shape":"image","label":label,"meta":meta,"size":20,"font":{"size":10}})
            else:
                meta["type"] = "workstation"
                nodes.append({"id":1,"image":"/static/assets/img/ws_icon_4.png","shape":"image","label":label,"meta":meta,"size":12,"font":{"size":10}})
            logons = AgentLogon.query.filter(AgentLogon.host_id == id).distinct(AgentLogon.sid).all()
            for enum,logon in enumerate(logons,2):
                if logon.local_account:
                    user = AgentUser.query.filter(AgentUser.sid == logon.sid).first()
                else:
                    user = ADUser.query.filter(ADUser.objectsid == logon.sid).first()
                if user:
                    if hasattr(user,"objectsid"):
                        u_meta = {"pwdlastset":str(user.pwdlastset),"description":user.description or "None","domain":user.domain,"lastlogon":str(user.lastlogon),"sid":user.objectsid,"logoncount":user.logoncount,"managed":str(user.managed)}
                        username = user.name
                    else:
                        u_meta = {"pwdlastset":str(user.last_password_change),"description":user.comment or "None","domain":user.domain,"logoncount":user.num_logons,"sid":user.sid,"managed":str(user.managed)}
                        username = user.username
                    nodes.append({"id":enum,"image":"/static/assets/img/user_icon_4.png","shape":"image","label":username,"meta":meta,"size":20,"font":{"size":10},"title":username})
                edges.append({"from":1,"to":enum,"length":200,"label":a.local_addr,"font":{"strokeWidth":.5,"color":"gray","strokeColor":"gray","size":10,"align":"bottom"},"width":1})
                    #edges.append({"from":1,"to":enum,"length":150})
        return {"nodes":nodes,"edges":edges}

    # User Logon VIS JS map
    def get_logon_map(self,sid,accounttype="local"):
        nodes = []
        edges = []
        if accounttype == "local":
            u = AgentUser.query.filter(AgentUser.sid == sid).order_by(AgentUser.id.desc()).first()
            if u:
                sid = u.sid
                name = "{} (Local)".format(u.username)
                u_meta = {"pwdlastset":str(u.last_password_change),"description":u.comment or "None","domain":u.domain,"logoncount":u.num_logons,"sid":u.sid,"managed":str(u.managed)}
        else:
            #u = ADUser.query.get(id)
            u = ADUser.query.filter(ADUser.objectsid == sid).order_by(ADUser.id.desc()).first()
            if u:
                sid = u.objectsid
                name = "{} (Domain)".format(u.name)
                u_meta = {"pwdlastset":str(u.pwdlastset),"description":u.description or "None","domain":u.domain,"lastlogon":str(u.lastlogon),"sid":u.objectsid,"logoncount":u.logoncount,"managed":str(u.managed)}
        if u:
            nodes.append({"id":1,"image":"/static/assets/img/user_icon_4.png","shape":"image","label":name,"meta":u_meta,"size":35,"font":{"size":12}})
            #logons = AgentLogon.query.filter(AgentLogon.sid == sid).all()
            logons = AgentLogon.query.filter(AgentLogon.sid == sid).distinct(AgentLogon.host_id).all()
            for enum,logon in enumerate(logons,2):
                #logons_by_host = AgentLogon.query.filter(AgentLogon.sid == sid).filter(AgentLogon.host_id == logon.host_id).all()
                host = Agent.query.get(logon.host_id)
                if host:
                    meta = {"hostname":host.hostname,"domain_joined":str(host.domain_joined),"domain":host.domain,"local_ip":host.local_addr,"is_dc":str(host.is_dc),"os":host.edition,"type":host.installtype,"host_id":host.id}
                    #label = "{} ({})".format(host.hostname,host.local_addr)
                    label = "{}".format(host.hostname)
                    if host.installtype.lower() in ("server"):
                        meta["type"] = "server"
                        nodes.append({"id":enum,"image":"/static/assets/img/server_icon_4.png","shape":"image","label":label,"meta":meta,"size":20,"font":{"size":10},"title":host.edition})
                    else:
                        meta["type"] = "workstation"
                        nodes.append({"id":enum,"image":"/static/assets/img/ws_icon_4.png","shape":"image","label":label,"meta":meta,"size":12,"font":{"size":10},"title":host.edition})
                    edges.append({"from":1,"to":enum,"length":200,"label":host.local_addr,"font":{"strokeWidth":.5,"color":"gray","strokeColor":"gray","size":10,"align":"bottom"},"width":1})
                    #edges.append({"from":1,"to":enum,"length":150})
        return {"nodes":nodes,"edges":edges}

    def get_logon_host_analytics(self,id):
        data = {"users":[],"total_logons":0,"uniq_priv_user_logons":0,"total_priv_logons":0,"domain_user_logons":0,"local_user_logons":0,"uniq_reg_user_logons":0}


        a = Agent.query.get(id)
        if a:
            data["hostname"] = a.hostname
            data["host_type"] = a.installtype
            data["os"] = a.edition
        # total logons
        total_logons = AgentLogon.query.filter(AgentLogon.host_id == id).count()
        data["total_logons"] = total_logons

        uniq_reg_user_logons = AgentLogon.query.filter(AgentLogon.host_id == id).filter(AgentLogon.is_priv != "1").distinct(AgentLogon.sid).count()
        data["uniq_reg_user_logons"] = uniq_reg_user_logons

        logon_data = DynamicQuery(
            model="agentlogon",
            filter=[("host_id", 'eq', id)],
            groupby=[("username","count"),("is_priv","group"),("sid","group"),("local_account","group")],
            as_json=True
        ).generate()
        for record in logon_data["data"]:
            record["percentage_of_total_logon"] = round((int(record["count"]) / total_logons)*100,1)
            if record["is_priv"] == "1":
                record["is_priv"] = "yes"
                data["uniq_priv_user_logons"] += 1
                data["total_priv_logons"] += int(record["count"])
            else:
                record["is_priv"] = "no"
            if record["local_account"].lower() != "true":
                data["domain_user_logons"] += 1
            else:
                data["local_user_logons"] += 1
            data["users"].append(record)
        print(data)
        if data["total_logons"]:
            data["percentage_logons_of_priv_users"]= round((data["total_priv_logons"] / data["total_logons"])*100,1)
        else:
            data["percentage_logons_of_priv_users"] = 0
        users = sorted(data["users"], key=lambda k: k['count'],reverse=True)
        data["users"] = users

        return data


    def get_logon_user_analytics(self,sid):
        data = {"percentage_logon_per_host":{},"uniq_host_logons":0,"total_logons":0,"total_server_logons":0,"total_wks_logons":0,"uniq_server_logons":0,"uniq_wks_logons":0,"hosts":[],"per_of_server_logons":0,"per_of_wks_logons":0}
        u = AgentUser.query.filter(AgentUser.sid == sid).first()
        if not u:
            u = ADUser.query.filter(ADUser.objectsid == sid).first()
            username = u.samaccountname
            usid = u.objectsid
        else:
            username = u.username
            usid = u.sid

        if u:
            data["username"] = username
            data["domain"] = u.domain
            data["is_priv"] = u.is_priv
            data["sid"] = usid

        total_count_of_logons = AgentLogon.query.filter(AgentLogon.sid == sid).count()
        logon_on_host_occur = DynamicQuery(
            model="agentlogon",
            filter=[("sid", 'eq', sid)],
            groupby=[("host_name","count"),("host_id","group")],
            as_json=True
        ).generate()
        data["uniq_host_logons"] = logon_on_host_occur["total"]
        data["total_logons"] = total_count_of_logons
        host_ids = []
        # generate logon percentage per host
        for logon in logon_on_host_occur["data"]:
            per_of_total_logon = round((int(logon["count"]) / total_count_of_logons) * 100,1)
            data["percentage_logon_per_host"][logon["host_name"]] = per_of_total_logon

            if logon["host_id"] not in host_ids:
                a = Agent.query.get(logon["host_id"])
                if a.installtype.lower() == "server":
                    htype = "server"
                    data["total_server_logons"] += int(logon["count"])
                    data["uniq_server_logons"] += 1
                else:
                    htype = "workstation"
                    data["total_wks_logons"] += int(logon["count"])
                    data["uniq_wks_logons"] += 1
                temp = {"hostname":logon["host_name"],"total_logons":logon["count"],"percentage_of_total_logons":per_of_total_logon,"type":htype,"id":logon["host_id"]}
                data["hosts"].append(temp)
                host_ids.append(logon["host_id"])
        if data["total_logons"]:
            data["per_of_server_logons"] = round((data["total_server_logons"] / data["total_logons"])*100,1)
            data["per_of_wks_logons"] = round((data["total_wks_logons"] / data["total_logons"])*100,1)

        hosts = sorted(data["hosts"], key=lambda k: k['total_logons'],reverse=True)
        data["hosts"] = hosts

        return data
