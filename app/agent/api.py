from flask import Blueprint,jsonify, request, current_app,send_file
from app.agent import rest
from app.utils.decorators import login_required, roles_required, agent_auth, site_key_required
from app.utils.operations import AgentOps, GroupOps, JobOps, AgentCmdOps
from app.utils.db_helper import DynamicQuery
from app.models import *
from datetime import datetime,timedelta
from app.utils.misc import lookup_ip,enrich_auditkey
import ipaddress
from app.utils.ad_helper import ADHelper
from app.utils.agent_helper import AgentHelper
from app.utils.data_formats import convert_to_datatables,convert_to_chartjs
from app.utils.queue_helper import SQSHelper,RMQHelper
import json

@rest.route("/pwd-last-changed", methods=["GET"])
@login_required
def buckets_pwd_changed():
    users = ADHelper().password_last_changed_buckets_ex()
    data = convert_to_chartjs(users)
    return jsonify(data)

@rest.route("/local/pwd-last-changed", methods=["GET"])
@login_required
def buckets_local_pwd_changed():
    users = AgentHelper().password_last_changed_buckets()
    data = convert_to_chartjs(users)
    return jsonify(data)

'''
@rest.route("/auditkeys/noncompliant-hosts", methods=["GET","POST"])
@login_required
def get_auditkey_noncompliant_hosts():
    result = DynamicQuery(
        model="agentauditkey",
        as_json=True,
    )
    AgentAuditKey.query
'''

@rest.route("/data/<string:model>", methods=["GET","POST"])
@login_required
def get_agent_events(model):
    '''
    API for sqlalchemy database tables
    '''
    if request.method == "POST":
        result = DynamicQuery(
          model="users",
          request_args=request.args,
          data=request.get_json(silent=True)
        )
        response = result.generate()
        return jsonify(response)


    else:
      aid = request.args.get('aid', default = None, type = str)
      hostname = request.args.get('hostname', default = None, type = str)
      filter=[]

      if aid or hostname:
        filter = [("host_id","eq",aid)]

      result = DynamicQuery(
        model=model,
        request_args=request.args,
        filter=filter,
        qjson=request.get_json(silent=True)
      )
      response = result.generate()
      return jsonify(response)

@rest.route("/manage/local/accounts/<aid>", methods=["GET"])
@agent_auth
def get_managed_local_accounts(aid,agentobj=None):
    data = VaultHelper(aid).get_managed_local_accounts_ready_for_rotation()
    return jsonify({"accounts":data})

@rest.route("/manage/ad/accounts/<aid>", methods=["GET"])
@agent_auth
def get_managed_ad_accounts(aid,agentobj=None):
    data = []
    if agentobj.advaulter:
        data = VaultHelper(aid).get_managed_ad_accounts_ready_for_rotation()
    return jsonify({"accounts":data})

@rest.route("/collection/set-localaccount/<aid>", methods=["POST"])
@agent_auth
def set_managed_local_accounts(aid,agentobj=None):
    # save the results of the password change to the database
    response = request.get_json()["dataset"]
    VaultHelper(aid).set_local_account_password_sync(response)
    return jsonify({"message":"ok"})

@rest.route("/collection/set-adaccount/<aid>", methods=["POST"])
@agent_auth
def set_managed_ad_accounts(aid,agentobj=None):
    # save the results of the password change to the database
    response = request.get_json()["dataset"]
    if agentobj.advaulter:
        VaultHelper(aid).set_ad_account_password_sync(response)
    return jsonify({"message":"ok"})

@rest.route("/health/<aid>",methods=["POST"])
@agent_auth
def agent_health(aid,agentobj=None):
#    agent = Agent.query.get(aid)
    db.session.close() # close session

    record = request.get_json()
    record["last_active"] = datetime.utcnow()
    result = DynamicQuery(
        model="agent",
        crud="update",
        filter=[("id","eq",aid)],
        data=record
    ).generate()
    return jsonify({"adcollector":agentobj.adcollector,"advaulter":agentobj.advaulter,"rtr":agentobj.rtr,"update":agentobj.update,"uninstall":agentobj.uninstall})

@rest.route("/version/<aid>")
@agent_auth
def agent_version(aid,agentobj=None):
    agentobj.update = 0
    db.session.commit()
    version = AgentOps(aid).get_version()
    return jsonify({"version":version})

@rest.route("/update/<aid>")
@agent_auth
def agent_update(aid,agentobj=None):
    agentobj.update = 0 # set update back to 0 (so agent doesnt keep trying to update forever)
    db.session.commit()
    filename = "/home/bmarshall/my_app/app/agent/files/agent7_installer.exe"
    return send_file(filename,as_attachment=True)

@rest.route("/valid-cmd/rtr/<aid>",methods=["GET"])
@agent_auth
def agent_command(aid,agentobj=None):
    return jsonify({"commands":AgentOps(aid).get_cmd()})

@rest.route("/registry/runkeys/<aid>",methods=["GET"])
@agent_auth
def agent_registry_runkeys(aid,agentobj=None):
    return 1

@rest.route("/registry/auditkeys/<aid>",methods=["GET"])
@agent_auth
def agent_registry_auditkeys(aid,agentobj=None):
    return jsonify({"keys":AgentOps(aid).get_auditkey()})

@rest.route("/rtr/<aid>",methods=["GET","POST"])
@login_required
def agent_rtr(aid,agentobj=None):
    '''Shell commands are added to the database for the agents to query and execute'''
    if request.method == "GET": # UI checking for updates
        id = request.args.get('id', default = None, type = int)
        p = db.session.query(AgentInteract).filter(AgentInteract.id==id).first()
        result = DynamicQuery(
                model="agentinteract",
                getfirst=True,
                filter=[("id","eq",id)]
        )
        response = result.generate()
        if response.get("count"):
            r = response["data"][0]
            return jsonify({"message":"Data returned from agent.","type":"success","id":r.id,
                "complete":r.complete,"data":r.data,"cwd":r.cwd})
        return jsonify({"message":"Command not complete.","type":"info","complete":0})
    elif request.method == "POST": # UI adding new commands
        dataset = request.get_json()
        dataset["host_id"] = aid
        result = DynamicQuery(
            model="agentinteract",
            crud="insert",
            data=dataset
        )
        response = result.generate()
        return jsonify({"message":"Sending the command to the agent.","type":"info","id":response.get("id")})

@rest.route("/interactive/<aid>",methods=["GET","POST"])
@agent_auth
def agent_interactive(aid,agentobj=None):
    '''Agent checking in to gather shell commands'''
    if request.method == "GET":
        result = DynamicQuery(
            model="AgentInteract",
            orderby=("id","desc"),
            getfirst=True,
            as_json=True,
            filter=[("host_id","eq",request.headers.get("aid")),("complete", 'eq', 0),
                ("date_added","gt",datetime.utcnow() - timedelta(minutes=10))],
        )
        response = result.generate()
        if response.get("total"):
            return jsonify({"response":response["data"][0]})
        return jsonify({})

    elif request.method == "POST": # agent posting results of a command
        response = request.get_json()
        response = response["dataset"]
        result = DynamicQuery(
            model="AgentInteract",
            data={"data":response["output"],"cwd":response["context"]["cwd"],"complete":1},
            filter=[("id", 'eq',response["id"])],
            crud="update"
        )
        response = result.generate()
        return jsonify({"message":"ok"})

@rest.route("/register/<aid>",methods=["POST"])
@site_key_required
def register_agent(aid):
    '''Agent registering with the server'''
    registered = 0
    result = Agent.query.get(aid)
    if result: # agent registered already
        registered = 1
        token = result.token
    else: # adding new agent
        data = request.get_json()
        data["public_addr"] = request.remote_addr
        major,minor,fix = data.get("version").split(".")
        data["major"] = major
        data["minor"] = minor
        data["fix"] = fix

        # get the install group from agent
        install_group = data.get("install_group","default")

        # geoip
        geo = lookup_ip(request.remote_addr)
        if geo: #make sure it is a global ip
            data["country_code"] = geo.country_code
            data["country_name"] = geo.country_name
            data["region_name"] = geo.region_name
            data["city_name"] = geo.city_name
            data["lat"] = geo.latitude
            data["long"] = geo.longitude

        if install_group == "default":
            default_cmd = AgentCmdOps("default_cmd").find_or_create_agentcmd(current_app.config["DEFAULT_CMD"],10)
            default_job = JobOps("default_job").find_or_create_job(current_app.config["DEFAULT_JOB"],10)
            default_group = GroupOps(install_group).find_or_create_group(install_group,"1.0.0",default_job,default_cmd)
        else:
            default_group = GroupOps(install_group).find_or_create_group(install_group,"1.0.0")
        create_agent = AgentOps(aid).find_or_create_agent(group=default_group,commit=True,**data)
        token = create_agent.token
        registered = 1
    return jsonify({"registered":registered,"token":token})

@rest.route("/collection/get-auditkeys/<aid>",methods=["POST"])
@agent_auth
def get_auditkeys(aid,agentobj=None):
    response = request.get_json()
    if response["dataset"]:
        enrich = enrich_auditkey(response["dataset"]) #[{"key":"path\\","value":1}]
        agentobj.compliance_grade = enrich["grade"]
        agentobj.total_compliance_checks = enrich["total"]
        agentobj.compliant = enrich["compliant"]
        agentobj.non_compliant = enrich["non_compliant"]
        agentobj.percentage_compliant = enrich["percentage_compliant"]
        db.session.commit()
#    record["host_name"] = AgentOps(aid).get_hostname()
        for record in enrich["results"]:
            record["host_id"] = aid
            result = DynamicQuery(
                model="agentauditkey",
                crud="update",
                filter=[("host_id","eq",aid),("key","eq",record["key"]),("value","eq",record["value"])],
                data=record
            )
            if result.generate().get("result") is False:
                print("error",request.path)
    return jsonify({"response":1})

@rest.route("/collection/get-memory/<aid>",methods=["POST"])
@agent_auth
def get_memory(aid,agentobj=None):
    response = request.get_json()
    if response.get("dataset"):
        RMQHelper().send("agentmemory",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="agentmemory",
            crud="update",
            filter=[("host_id","eq",aid)],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-disk/<aid>",methods=["POST"])
@agent_auth
def get_disk(aid,agentobj=None):
    response = request.get_json()
    if response.get("dataset"):
        print(response.get("dataset"))
        RMQHelper().send("agentdisk",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="agentdisk",
            crud="update",
            filter=[("host_id","eq",aid),("device","eq",record["device"])],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-pipe/<aid>",methods=["POST"])
@agent_auth
def get_pipe(aid,agentobj=None):
    response = request.get_json()
    if response.get("dataset"):
        RMQHelper().send("agentpipe",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="agentpipe",
            crud="update",
            filter=[("host_id","eq",aid),("name","eq",record["name"])],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-printer/<aid>",methods=["POST"])
@agent_auth
def get_printer(aid,agentobj=None):
    response = request.get_json()
    if response.get("dataset"):
        RMQHelper().send("agentprinter",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="agentprinter",
            crud="update",
            filter=[("host_id","eq",aid),("name","eq",record["name"])],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-schtask/<aid>",methods=["POST"])
@agent_auth
def get_schtask(aid,agentobj=None):
    response = request.get_json()
    '''
    if response.get("dataset"):
        RMQHelper().send("agentschtask",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="agentschtask",
            crud="update",
            filter=[("host_id","eq",aid),("command","eq",record.get("command"))],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    return jsonify({"response":1})

@rest.route("/collection/get-patch/<aid>",methods=["POST"])
@agent_auth
def get_patch(aid,agentobj=None):
    response = request.get_json()
    if response.get("dataset"):
        RMQHelper().send("agentpatch",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="agentpatch",
            crud="update",
            filter=[("host_id","eq",aid),("hotfixid","eq",record["hotfixid"])],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-profile/<aid>",methods=["POST"])
@agent_auth
def get_profile(aid,agentobj=None):
    response = request.get_json()
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="agentprofile",
            crud="update",
            filter=[("host_id","eq",aid),("caption","eq",record["caption"])],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    return jsonify({"response":1})

@rest.route("/collection/get-logon/<aid>",methods=["POST"])
@agent_auth
def get_logon(aid,agentobj=None):
    response = request.get_json()
    '''
    if response.get("dataset"):
        RMQHelper().send("agentlogon",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="agentlogon",
            crud="update",
            filter=[("host_id","eq",aid),("username","eq",record.get("username")),("logonid","eq",record["logonid"])],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    return jsonify({"response":1})

@rest.route("/collection/get-netsession/<aid>",methods=["POST"])
@agent_auth
def get_netsession(aid,agentobj=None):
    response = request.get_json()
    if response.get("dataset"):
        RMQHelper().send("agentnetsession",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="agentnetsession",
            crud="update",
            filter=[("host_id","eq",aid),("user_name","eq",record["user_name"]),("client_name","eq",record["client_name"])],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-session/<aid>",methods=["POST"])
@agent_auth
def get_session(aid,agentobj=None):
    response = request.get_json()
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="agentsession",
            crud="update",
            filter=[("host_id","eq",aid),("logonid","eq",record["logonid"])],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    return jsonify({"response":1})

@rest.route("/collection/get-netuse/<aid>",methods=["POST"])
@agent_auth
def get_netuse(aid,agentobj=None):
    response = request.get_json()
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="agentnetuse",
            crud="update",
            filter=[("host_id","eq",aid),("remote","eq",record["remote"])],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    return jsonify({"response":1})

@rest.route("/collection/get-connection/<aid>",methods=["POST"])
@agent_auth
def get_connection(aid,agentobj=None):
    response = request.get_json()
#haaaaa
    if response.get("dataset"):
#        SQSHelper().send("agentnet",json.dumps(response["dataset"]))
        RMQHelper().send("agentnet",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        try:
            record["private"] = ipaddress.ip_address(record.get("raddr")).is_private
        except:
            pass

        result = DynamicQuery(
            model="agentnet",
            crud="update",
#            filter=[("host_id","eq",aid),("pname","eq",record["pname"]),("rport","eq",str(record["rport"])),
#                ("lport","eq",str(record["lport"])),("pid","eq",str(record["pid"])),("family","eq",record["family"])],
            filter=[("host_id","eq",aid),("pname","eq",record["pname"]),("raddr","eq",str(record.get("raddr"))),
                ("pid","eq",str(record["pid"]))],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-software/<aid>",methods=["POST"])
@agent_auth
def get_software(aid,agentobj=None):
    response = request.get_json()
    if response.get("dataset"):
        RMQHelper().send("agentsoftware",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="agentsoftware",
            crud="update",
            filter=[("host_id","eq",aid),("displayname","eq",record.get("displayname"))],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-updates/<aid>",methods=["POST"])
@agent_auth
def get_updates(aid,agentobj=None):
    response = request.get_json()
    if response.get("dataset"):
        RMQHelper().send("agentupdates",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="agentupdates",
            crud="update",
            filter=[("host_id","eq",aid),("guid","eq",record.get("guid"))],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-system/<aid>",methods=["POST"])
@agent_auth
def get_system(aid,agentobj=None):
    response = request.get_json()
    if response.get("dataset"):
        RMQHelper().send("agentsystem",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="agentsystem",
            crud="update",
            filter=[("host_id","eq",aid)],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-share/<aid>",methods=["POST"])
@agent_auth
def get_share(aid,agentobj=None):
    response = request.get_json()
    if response.get("dataset"):
        RMQHelper().send("agentshare",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="agentshare",
            crud="update",
            filter=[("host_id","eq",aid),("name","eq",record["name"]),("path","eq",record["path"])],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-startup/<aid>",methods=["POST"])
@agent_auth
def get_startup(aid,agentobj=None):
    response = request.get_json()
    if response.get("dataset"):
        RMQHelper().send("agentstartup",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="agentstartup",
            crud="update",
            filter=[("host_id","eq",aid),("username","eq",record["username"]),("command","eq",record["command"])],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-netadapter/<aid>",methods=["POST"])
@agent_auth
def get_netadapter(aid,agentobj=None):
    response = request.get_json()
    if response.get("dataset"):
        RMQHelper().send("agentadapter",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="agentadapter",
            crud="update",
            filter=[("host_id","eq",aid),("caption","eq",record["caption"])],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-process/<aid>",methods=["POST"])
@agent_auth
def get_process(aid,agentobj=None):
    #haaaaaa
    response = request.get_json()
    if response.get("dataset"):
#        SQSHelper().send("agentprocess",json.dumps(response["dataset"]))
        RMQHelper().send("agentprocess",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        #print(record)
        record["host_id"] = aid
        result = DynamicQuery(
            model="agentprocess",
            crud="update",
#            filter=[("host_id","eq",aid),("image","eq",record["image"]),("create_time","eq",record["create_time"])],
            filter=[("host_id","eq",aid),("pid","eq",record["pid"]),("ppid","eq",record.get("ppid"))],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-service/<aid>",methods=["POST"])
@agent_auth
def get_service(aid,agentobj=None):
    response = request.get_json()
#haaaaa
    if response.get("dataset"):
#        SQSHelper().send("agentservice",json.dumps(response["dataset"]))
        RMQHelper().send("agentservice",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="agentservice",
            crud="update",
            filter=[("host_id","eq",aid),("image","eq",record["image"]),("command","eq",record.get("command"))],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-user/<aid>",methods=["POST"])
@agent_auth
def get_user(aid,agentobj=None):
    response = request.get_json()
    '''
    if response.get("dataset"):
        RMQHelper().send("agentuser",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="agentuser",
            crud="update",
            filter=[("host_id","eq",aid),("sid","eq",record.get("sid"))],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    return jsonify({"response":1})

@rest.route("/collection/get-group/<aid>",methods=["POST"])
@agent_auth
def get_group(aid,agentobj=None):
    response = request.get_json()
    if response.get("dataset"):
        RMQHelper().send("agentgroup",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="agentgroup",
            crud="update",
            filter=[("host_id","eq",aid),("group","eq",record.get("group")),("members_count","eq",record.get("members_count"))],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-platform/<aid>",methods=["POST"])
@agent_auth
def get_platform(aid,agentobj=None):
    response = request.get_json()
    remote_ip = request.remote_addr
#    remote_ip="71.163.90.130" #for testing
    for record in response.get("dataset"):
        # remove ad collector bit if exists
        record.pop("adcollector",None)
        record.pop("advaulter",None)

        if agentobj.public_addr != remote_ip: # if ip_address changed, update lat/long
            geo = lookup_ip(remote_ip)
            if geo: #make sure it is a global ip
                record["country_code"] = geo.country_code
                record["country_name"] = geo.country_name
                record["region_name"] = geo.region_name
                record["city_name"] = geo.city_name
                record["lat"] = geo.latitude
                record["long"] = geo.longitude

        record["public_addr"] = remote_ip
        result = DynamicQuery(
            model="agent",
            crud="update",
            filter=[("id","eq",aid)],
            data=record
        )
        if result.generate().get("result") is False:
            print("insert error")
    return jsonify({"response":1})

@rest.route("/job/<aid>",methods=["POST"])
@agent_auth
def get_job(aid,agentobj=None):
#haaaa
    # return the job
    data = {"jobset":AgentOps(aid).get_job()}
    data["adcollector"] = agentobj.adcollector
    data["advaulter"] = agentobj.advaulter
    data["rtr"] = agentobj.rtr
    data["update"] = agentobj.update
    data["uninstall"] = agentobj.uninstall

    # update agent table
    record = request.get_json()
    record["last_active"] = datetime.utcnow()
    result = DynamicQuery(
        model="agent",
        crud="update",
        filter=[("id","eq",aid)],
        data=record
    ).generate()

    return jsonify(data)

## ACTIVE DIRECTORY SECTION
@rest.route("/collection/get-ad-ou/<aid>",methods=["POST"])
@agent_auth
def get_ad_ou(aid,agentobj=None):
    response = request.get_json()
    if response.get("dataset"):
        RMQHelper().send("ad_ou",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="ad_ou",
            crud="update",
            filter=[("name","eq",record.get("name"))],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-ad-gpo/<aid>",methods=["POST"])
@agent_auth
def get_ad_gpo(aid,agentobj=None):
    response = request.get_json()
    if response.get("dataset"):
        RMQHelper().send("ad_gpo",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="ad_gpo",
            crud="update",
            filter=[("distinguishedname","eq",record.get("distinguishedname"))],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-ad-sysvol/<aid>",methods=["POST"])
@agent_auth
def get_ad_sysvol(aid,agentobj=None):
    response = request.get_json()
    if response.get("dataset"):
        RMQHelper().send("ad_sysvol",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="ad_sysvol",
            crud="update",
            filter=[("path","eq",record.get("path")),("acecount","eq",record["acecount"])],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-ad-domain/<aid>",methods=["POST"])
@agent_auth
def get_ad_domain(aid,agentobj=None):
    response = request.get_json()
    if response.get("dataset"):
        RMQHelper().send("ad_domain",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="ad_domain",
            crud="update",
            filter=[("dc","eq",record.get("dc"))],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-ad-dc/<aid>",methods=["POST"])
@agent_auth
def get_ad_dc(aid,agentobj=None):
    response = request.get_json()
    if response.get("dataset"):
        RMQHelper().send("ad_dc",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="ad_dc",
            crud="update",
            filter=[("name","eq",record.get("name"))],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-ad-user/<aid>",methods=["POST"])
@agent_auth
def get_ad_user(aid,agentobj=None):
    response = request.get_json()
    if response.get("dataset"):
        RMQHelper().send("ad_user",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="ad_user",
            crud="update",
            filter=[("objectsid","eq",record.get("objectsid")),("samaccountname","eq",record.get("samaccountname"))],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-ad-group/<aid>",methods=["POST"])
@agent_auth
def get_ad_group(aid,agentobj=None):
    response = request.get_json()
    if response.get("dataset"):
        RMQHelper().send("ad_group",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
#        print(record["name"])
        record["host_id"] = aid
        result = DynamicQuery(
            model="ad_group",
            #crud="insert",
            crud="update",
            filter=[("objectsid","eq",record.get("objectsid")),("members_count","eq",record.get("members_count"))],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})

@rest.route("/collection/get-ad-computer/<aid>",methods=["POST"])
@agent_auth
def get_ad_computer(aid,agentobj=None):
    response = request.get_json()
    if response.get("dataset"):
        RMQHelper().send("ad_computer",json.dumps(response["dataset"]))
    '''
    for record in response.get("dataset"):
        record["host_id"] = aid
        result = DynamicQuery(
            model="ad_computer",
            crud="update",
            filter=[("distinguishedname","eq",record.get("distinguishedname"))],
            data=record
        )
        if result.generate().get("result") is False:
            print("error",request.path)
    '''
    return jsonify({"response":1})
