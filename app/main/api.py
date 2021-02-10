from flask import jsonify,current_app,request,url_for
from app.models import User,Group,AgentInteract,Insight,AgentUser,Agent,AgentLogon,ADUser
from app.main import rest
from app.utils.decorators import login_required, roles_required
from flask_login import current_user
from app import db
from app.utils.data_formats import convert_to_datatables,convert_to_chartjs
from app.utils.db_helper import DynamicQuery
from app.utils.ad_helper import ADHelper
from app.utils.agent_helper import AgentHelper
from app.utils.pam_helper import PamHelper
import datetime
import json
import arrow

@rest.route('/priv/local-users')
#@login_required
def api_get_priv_local_users():
    data = []
    for user in PamHelper().get_priv_users_local():
        data.append(user.id)
    return jsonify({"data":data})

@rest.route('/priv/domain-users')
#@login_required
def api_get_priv_domain_users():
    data = []
    for user in PamHelper().get_priv_users_domain():
        data.append(user.id)
    return jsonify({"data":data})

@rest.route('/priv/process')
#@login_required
def api_get_priv_process():
    data = []
    for process in PamHelper().get_process_for_priv_users():
        data.append(process.id)
    return jsonify({"data":data})

@rest.route('/priv/schtask')
#@login_required
def api_get_priv_schtask():
    data = []
    for task in PamHelper().get_schtask_for_priv_users():
        data.append(task.id)
    return jsonify({"data":data})

@rest.route('/priv/service')
#@login_required
def api_get_priv_service():
    data = []
    for service in PamHelper().get_service_for_priv_users():
        data.append(service.id)
    return jsonify({"data":data})

@rest.route('/priv/startup')
#@login_required
def api_get_priv_startup():
    data = []
    for su in PamHelper().get_startup_for_priv_users():
        data.append(su.id)
    return jsonify({"data":data})

@rest.route('/priv/logon')
#@login_required
def api_get_priv_logon():
    data = []
    for logon in PamHelper().get_logon_for_priv_users():
        data.append(logon.id)
    return jsonify({"data":data})

@rest.route('/priv/connection')
#@login_required
def api_get_priv_connection():
    data = []
    for conn in PamHelper().get_connections_for_priv_users():
        data.append(conn.id)
    return jsonify({"data":data})

@rest.route('/logon-map/analytics/host/<int:id>')
@login_required
def api_logonmap_host_analytics(id):
    return AgentHelper().get_logon_host_analytics(id)

@rest.route('/logon-map/analytics/user/<string:sid>')
@login_required
def api_logonmap_user_analytics(sid):
    return AgentHelper().get_logon_user_analytics(sid)

@rest.route('/groups/<id>/agents', methods = ['GET'])
@login_required
def agents_in_group(id):
    '''Agents in Group'''
    data = {"data":[],"columns":["aid","hostname","version"]}
    group = Group.query.get(id)
    if group:
        agents=group.agents.all()
        for agent in agents:
            data["data"].append([agent.id,agent.hostname,agent.version])
    return jsonify(data)

@rest.route('/rtr/audit',methods = ['GET'])
@roles_required("rtr")
def get_rtr_sessions():
    return db.session.query(AgentInteract).distinct(AgentInteract.session).limit(100).all()

@rest.route('/insight/data/<id>', methods = ['GET'])
@login_required
def view_insight_data(id):
    data_dict = {"draw":0,"data": [],"count":0,"columns":[]}
    insight = Insight.query.get(id)
    if insight:
        data = insight.data
        if not isinstance(data,list):
            data = [data]
        # get fields
        if data:
            fields = data[0].keys()
            for record in data:
                data_dict["count"] += 1
                temp_list = []
                for field in fields:
                    try:
                        temp_list.append(record[field])
                        if field not in data_dict["columns"]:
                            data_dict["columns"].append(field)
                    except KeyError:
                        print("key: {%s} does not exist or restricted" % (field))
                data_dict["data"].append(temp_list)
    return jsonify(data_dict)

@rest.route('/investigate/user/local/logon/<int:id>', methods = ['GET'])
@login_required
def api_inv_user_local_logon(id):
    user = AgentUser.query.get(id)
    if user:
        server = 0
        workstation = 0
        seen = []
        host_data = []
        data = AgentLogon.query.filter(AgentLogon.sid == user.sid).all()
        for logon in data:
            host_id = logon.host_id
            if host_id not in seen:
                seen.append(host_id)
                host = Agent.query.get(host_id)
                if host:
                     host_data.append(host)

@rest.route('/vault/privileged/accounts', methods = ['GET'])
@login_required
def api_vault_priv_accounts():
     data = []
     as_count = request.args.get('as_count', default = 0, type = int)
     as_datatables = request.args.get('as_datatables', default = 0, type = int)

     domain = ADUser.query.filter(ADUser.is_priv == "1").all()
     local = AgentUser.query.filter(AgentUser.is_priv == "1").all()

     if as_datatables:
         for record in domain:
             del record.__dict__["_sa_instance_state"]
             record.sid = record.objectsid
             data.append(vars(record))
         for record in local:
             del record.__dict__["_sa_instance_state"]
             record.name = record.username
             data.append(vars(record))
         return convert_to_datatables(data,fields=["id","name","sid","domain","managed","last_password_sync","date_added"])
     return jsonify({"count":len(domain+local)})

@rest.route('/vault/privileged/managed/accounts', methods = ['GET'])
@login_required
def api_vault_priv_managed_accounts():
     domain = ADUser.query.filter(ADUser.managed == True).filter(ADUser.is_priv == "1").all()
     local = AgentUser.query.filter(AgentUser.managed == True).filter(AgentUser.is_priv == "1").all()
     return jsonify({"count":len(domain+local)})

@rest.route('/vault/privileged/unmanaged/accounts', methods = ['GET'])
@login_required
def api_vault_priv_unmanaged_accounts():
     domain = ADUser.query.filter(ADUser.managed == False).filter(ADUser.is_priv == "1").all()
     local = AgentUser.query.filter(AgentUser.managed == False).filter(AgentUser.is_priv == "1").all()
     return jsonify({"count":len(domain+local)})

@rest.route('/vault/privileged/domain/group/metrics', methods = ['GET'])
@login_required
def api_vault_priv_domain_group_metrics():
    data = ADHelper().get_users_in_privileged_groups_by_group(include_members=False)
    return convert_to_datatables(data)

@rest.route('/privileged/assets/percentages', methods = ['GET'])
@login_required
def api_priv_assets_percentages():
#haaaaa
    total_users = 0
    total_priv_users = 0
    # get all active users (from AD and local)
    all_active_ad_users = DynamicQuery(
        model="ad_user",
        filter=[("objectclass","eq","user"),("lastlogon","gt","60 days ago")],
        groupby=[("is_priv","count")],
        as_json=True,
    ).generate()
    if all_active_ad_users["count"]:
        for record in all_active_ad_users["data"]:
            total_users += int(record["count"])
            if record["is_priv"] == "1":
                total_priv_users += int(record["count"])

    all_active_local_users = DynamicQuery(
        model="agentuser",
        filter=[("last_logon","gt","60 days ago"),("local_account","eq",True)],
        groupby=[("is_priv","count")],
        as_json=True,
    ).generate()
    if all_active_local_users["count"]:
        for record in all_active_ad_users["data"]:
            total_users += int(record["count"])
            if record["is_priv"] == "1":
                total_priv_users += int(record["count"])
    per_of_priv_users = round((total_priv_users/total_users)*100,1)
    return {"percentage_of_priv_users":per_of_priv_users}
    # get all priv users

    # perform priv / total * 100
