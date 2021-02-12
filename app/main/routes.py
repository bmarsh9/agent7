from flask import Flask, request,url_for, render_template,redirect, flash, current_app,jsonify,session
from app.utils.decorators import login_required, roles_required,current_user,roles_accepted
from app import db
from app.main import ui
from app.models import *
from app.utils.operations import AgentOps, GroupOps, JobOps, AgentCmdOps
from datetime import datetime
from sqlalchemy import or_
from app.utils.db_helper import DynamicQuery
import ast
from app.utils.agent_helper import AgentHelper
import json
import arrow
from app.utils.misc import color_scheme

@ui.route('/map/user/<string:accounttype>/<string:sid>', methods = ['GET'])
@login_required
def user_logon_map(accounttype,sid):
    data = AgentHelper().get_logon_map(sid,accounttype=accounttype)
    return render_template("user_logon_map.html",data=data)

@ui.route('/map/host/<int:id>', methods = ['GET'])
@login_required
def host_logon_map(id):
    data = AgentHelper().get_logon_map_for_host(id)
    return render_template("host_logon_map.html",data=data)

@ui.route('/investigate/privileged/users', methods = ['GET'])
@login_required
def inv_priv_users():
    return render_template("inv_priv_users.html")

@ui.route('/process/image/<string:image>', methods = ['GET'])
@login_required
def view_single_process(image):
    return render_template("agent/view_single_process.html",image=image)

@ui.route('/software/name/<string:name>', methods = ['GET'])
@login_required
def view_single_software(name):
    return render_template("agent/view_single_software.html",name=name)

@ui.route('/schtask/name/<string:name>', methods = ['GET'])
@login_required
def view_single_schtask(name):
    return render_template("agent/view_single_schtask.html",name=name)

@ui.route('/startup/name/<string:name>', methods = ['GET'])
@login_required
def view_single_startup(name):
    return render_template("agent/view_single_startup.html",name=name)

@ui.route('/connection/ip/<string:raddr>', methods = ['GET'])
@login_required
def view_single_connection(raddr):
    return render_template("agent/view_single_connection.html",raddr=raddr)

@ui.route('/connection/region/<string:region>', methods = ['GET'])
@login_required
def view_single_connection_by_region(region):
    return render_template("agent/view_single_connection_by_region.html",region=region)

@ui.route('/share/name/<string:name>', methods = ['GET'])
@login_required
def view_single_share(name):
    return render_template("agent/view_single_share.html",name=name)

@ui.route('/logon/user/<string:sid>', methods = ['GET'])
@login_required
def view_single_logon_by_user(sid):
    user = AgentUser.query.filter(AgentUser.sid == sid).first()
    if not user:
        user = ADUser.query.filter(ADUser.objectsid == sid).first()
    return render_template("agent/view_single_logon_by_user.html",user=user)

@ui.route('/logon/host/<string:host>', methods = ['GET'])
@login_required
def view_single_logon_by_host(host):
    return render_template("agent/view_single_logon_by_host.html",host=host)

# --------------- INVESTIGATE
@ui.route('/investigate', methods = ['GET'])
@login_required
def investigate():
    users = []
    hosts = []
    search_type = request.args.get('search_type', default= None, type = str)
    # search by user
    if search_type == "username":
        username = request.args.get("username").strip()
        local_users = AgentUser.query.filter(AgentUser.username.ilike("%{}%".format(username))).filter(AgentUser.local_account == True).limit(10).all()
        domain_users = ADUser.query.filter(ADUser.cn.ilike("%{}%".format(username))).limit(10).all()
        users = (local_users + domain_users)
    # search by computer
    elif search_type == "hostname":
        hostname = request.args.get("hostname").strip()
        hosts = Agent.query.filter(Agent.hostname.ilike("%{}%".format(hostname))).limit(10).all()
    # search by agent
    elif search_type == "aid":
        aid = request.args.get("aid").strip()
        if aid:
            hosts = Agent.query.filter(Agent.id == int(aid)).all()

    return render_template("investigate.html",users=users,hosts=hosts)

@ui.route('/investigate/agent/<aid>', methods = ['GET'])
@login_required
def investigate_agent(aid):
    agent = Agent.query.filter(Agent.id == int(aid)).first()
    return render_template("investigate/agent_overview.html",agent=agent)

@ui.route('/investigate/agent/<aid>/logon', methods = ['GET'])
@login_required
def agent_logon(aid):
    agent = Agent.query.filter(Agent.id == int(aid)).first()
    return render_template("investigate/agent_logon.html",agent=agent)

@ui.route('/investigate/agent/<aid>/services', methods = ['GET'])
@login_required
def agent_services(aid):
    agent = Agent.query.filter(Agent.id == int(aid)).first()
    return render_template("investigate/agent_services.html",agent=agent)

@ui.route('/investigate/agent/<aid>/process', methods = ['GET'])
@login_required
def agent_process(aid):
    agent = Agent.query.filter(Agent.id == int(aid)).first()
    return render_template("investigate/agent_process.html",agent=agent)

@ui.route('/investigate/agent/<aid>/network', methods = ['GET'])
@login_required
def agent_network(aid):
    data = []
    for connect in AgentNet.query.filter(AgentNet.host_id == aid).filter(AgentNet.private == False).distinct(AgentNet.city_name).limit(50).all():
        data.append({"code":connect.country_code,"city":connect.city_name,"country":connect.country_name,"lat":connect.lat,"lon":connect.long})

    agent = Agent.query.filter(Agent.id == int(aid)).first()
    return render_template("investigate/agent_network.html",agent=agent,data=json.dumps(data))

@ui.route('/investigate/agent/<aid>/software', methods = ['GET'])
@login_required
def agent_software(aid):
    agent = Agent.query.filter(Agent.id == int(aid)).first()
    return render_template("investigate/agent_software.html",agent=agent)

@ui.route('/investigate/agent/<aid>/shares', methods = ['GET'])
@login_required
def agent_shares(aid):
    agent = Agent.query.filter(Agent.id == int(aid)).first()
    return render_template("investigate/agent_shares.html",agent=agent)

@ui.route('/investigate/agent/<aid>/schtask', methods = ['GET'])
@login_required
def agent_schtask(aid):
    agent = Agent.query.filter(Agent.id == int(aid)).first()
    return render_template("investigate/agent_schtask.html",agent=agent)

@ui.route('/investigate/agent/<aid>/startup', methods = ['GET'])
@login_required
def agent_startup(aid):
    agent = Agent.query.filter(Agent.id == int(aid)).first()
    return render_template("investigate/agent_startup.html",agent=agent)

@ui.route('/investigate/agent/<aid>/users', methods = ['GET'])
@login_required
def agent_users(aid):
    agent = Agent.query.filter(Agent.id == int(aid)).first()
    return render_template("investigate/agent_users.html",agent=agent)

@ui.route('/investigate/agent/<aid>/groups', methods = ['GET'])
@login_required
def agent_groups(aid):
    agent = Agent.query.filter(Agent.id == int(aid)).first()
    return render_template("investigate/agent_groups.html",agent=agent)

@ui.route('/investigate/agent/<aid>/groupmembers/<group>', methods = ['GET'])
@login_required
def agent_group_members(aid,group):
    agent = Agent.query.filter(Agent.id == int(aid)).first()
    group = AgentGroup.query.filter(AgentGroup.host_id == aid).filter(AgentGroup.group == group).order_by(AgentGroup.id.desc()).first()
    return render_template("investigate/agent_groupmembers.html",agent=agent,group=group)

@ui.route('/investigate/user/domain/<int:id>', methods = ['GET'])
@login_required
def investigate_domain_user(id):
    user = ADUser.query.get(id)
    if not user:
        flash("User not found!")
    return render_template("investigate/user/domain_user_overview.html",user=user)

@ui.route('/investigate/user/domain/<int:id>/process', methods = ['GET'])
@login_required
def domain_user_process(id):
    user = ADUser.query.get(id)
    if not user:
        flash("User not found!")
    return render_template("investigate/user/domain_user_process.html",user=user)

@ui.route('/investigate/user/domain/<int:id>/network', methods = ['GET'])
@login_required
def domain_user_network(id):
    user = ADUser.query.get(id)
    data = []
    for connect in AgentNet.query.filter(AgentNet.sid == user.objectsid).filter(AgentNet.private == False).distinct(AgentNet.city_name).limit(50).all():
        data.append({"code":connect.country_code,"city":connect.city_name,"country":connect.country_name,"lat":connect.lat,"lon":connect.long})
    if not user:
        flash("User not found!")
    return render_template("investigate/user/domain_user_network.html",user=user,data=data)

@ui.route('/investigate/user/domain/<int:id>/service', methods = ['GET'])
@login_required
def domain_user_service(id):
    user = ADUser.query.get(id)
    if not user:
        flash("User not found!")
    return render_template("investigate/user/domain_user_service.html",user=user)

@ui.route('/investigate/user/domain/<int:id>/schtask', methods = ['GET'])
@login_required
def domain_user_schtask(id):
    user = ADUser.query.get(id)
    if not user:
        flash("User not found!")
    return render_template("investigate/user/domain_user_schtask.html",user=user)

@ui.route('/investigate/user/domain/<int:id>/startup', methods = ['GET'])
@login_required
def domain_user_startup(id):
    user = ADUser.query.get(id)
    if not user:
        flash("User not found!")
    return render_template("investigate/user/domain_user_startup.html",user=user)

@ui.route('/investigate/user/domain/<int:id>/dependencies', methods = ['GET'])
@login_required
def domain_user_dependencies(id):
    user = ADUser.query.get(id)
    if not user:
        flash("User not found!")
    return render_template("investigate/user/domain_user_dependencies.html",user=user)

@ui.route('/investigate/user/domain/<int:id>/logon-history', methods = ['GET'])
@login_required
def domain_user_logon_history(id):
    user = ADUser.query.get(id)
    if not user:
        flash("User not found!")
    return render_template("investigate/user/domain_user_logon.html",user=user)

@ui.route('/investigate/user/local/<int:id>', methods = ['GET'])
@login_required
def investigate_local_user(id):
    user = AgentUser.query.get(id)
    if not user:
        flash("User not found!")
    return render_template("investigate/user/local_user_overview.html",user=user)

@ui.route('/investigate/user/local/<int:id>/risk', methods = ['GET'])
@login_required
def local_user_risk(id):
    user = AgentUser.query.get(id)
    if not user:
        flash("User not found!")
    return render_template("investigate/user/local_user_risk.html",user=user)

@ui.route('/investigate/user/local/<int:id>/logon-history', methods = ['GET'])
@login_required
def local_user_logon_history(id):
    user = AgentUser.query.get(id)
    if not user:
        flash("User not found!")
    return render_template("investigate/user/local_user_logon.html",user=user)

@ui.route('/investigate/user/local/<int:id>/process', methods = ['GET'])
@login_required
def local_user_process(id):
    user = AgentUser.query.get(id)
    if not user:
        flash("User not found!")
    return render_template("investigate/user/local_user_process.html",user=user)

@ui.route('/investigate/user/local/<int:id>/network', methods = ['GET'])
@login_required
def local_user_network(id):
    user = AgentUser.query.get(id)
    data = []
    for connect in AgentNet.query.filter(AgentNet.sid == user.sid).filter(AgentNet.private == False).distinct(AgentNet.city_name).limit(50).all():
        data.append({"code":connect.country_code,"city":connect.city_name,"country":connect.country_name,"lat":connect.lat,"lon":connect.long})
    if not user:
        flash("User not found!")
    return render_template("investigate/user/local_user_network.html",user=user,data=data)

@ui.route('/investigate/user/local/<int:id>/service', methods = ['GET'])
@login_required
def local_user_service(id):
    user = AgentUser.query.get(id)
    if not user:
        flash("User not found!")
    return render_template("investigate/user/local_user_service.html",user=user)

@ui.route('/investigate/user/local/<int:id>/schtask', methods = ['GET'])
@login_required
def local_user_schtask(id):
    user = AgentUser.query.get(id)
    if not user:
        flash("User not found!")
    return render_template("investigate/user/local_user_schtask.html",user=user)

@ui.route('/investigate/user/local/<int:id>/startup', methods = ['GET'])
@login_required
def local_user_startup(id):
    user = AgentUser.query.get(id)
    if not user:
        flash("User not found!")
    return render_template("investigate/user/local_user_startup.html",user=user)

@ui.route('/investigate/user/local/<int:id>/dependencies', methods = ['GET'])
@login_required
def local_user_dependencies(id):
    user = AgentUser.query.get(id)
    if not user:
        flash("User not found!")
    return render_template("investigate/user/local_user_dependencies.html",user=user)

@ui.route('/investigate/user/local/<int:id>/memberof', methods = ['GET'])
@login_required
def local_user_memberof(id):
    user = AgentUser.query.get(id)
    if not user:
        flash("User not found!")
    return render_template("investigate/user/local_user_memberof.html",user=user)

@ui.route('/privilege-use/user', methods = ['GET','POST'])
@login_required
def privilege_use_user():
    sorted_by = request.args.get('sorted_by', default= "total_logons", type = str)
    users = []
    data = PamHelper().get_priv_users()
    for user in data:
        if hasattr(user,"objectsid"):
            sid = user.objectsid
        else:
            sid = user.sid
        d = AgentHelper().get_logon_user_analytics(sid)
        if d:
            users.append(d)
    if users:
        users = sorted(users,key=lambda k: k[sorted_by],reverse=True)
    return render_template("account_management/privilege_use_user.html",users=users,sorted_by=sorted_by)

@ui.route('/privilege-use/host', methods = ['GET','POST'])
@login_required
def privilege_use_host():
    sorted_by = request.args.get('sorted_by', default= "total_priv_logons", type = str)
    hosts = []
    for agent in Agent.query.filter(Agent.uninstall == 0).all():
        d = AgentHelper().get_logon_host_analytics(agent.id)
        if d:
            hosts.append(d)
    if hosts:
        hosts = sorted(hosts, key=lambda k: k[sorted_by],reverse=True)
    return render_template("account_management/privilege_use_host.html",hosts=hosts,sorted_by=sorted_by)

@ui.route('/', methods = ['GET'])
@login_required
def dashboard():
    flash("This solution is a Endpoint Monitoring solution that collects and analyzes data from Windows endpoints. Feel free to look around and explore!",category="success")
    return redirect(url_for("agent_ui.panels"))
    data = []
    for agent in AgentNet.query.filter(AgentNet.private == False).distinct(AgentNet.city_name).limit(50).all():
        data.append({"code":agent.country_code,"city":agent.city_name,"country":agent.country_name,"lat":agent.lat,"lon":agent.long})
    return render_template("dashboard.html",data=json.dumps(data))

@ui.route('/insight', methods = ['GET','POST'])
@login_required
def insight():
    status  = None
    severity = None
    ease = None
    confidence = None
    module = None
    colors = color_scheme()
    if request.method == "POST": # filters applied
        q = db.session.query(Insight)
        status = request.form.get("status","None")
        module = request.form.get("module","None")
        severity = request.form.get("severity","None")
        ease = request.form.get("ease","None")
        confidence = request.form.get("confidence","None")

        if status and "None" not in status:
            q = q.filter(Insight.status == status)
        if module and "None" not in module:
            q = q.filter(Insight.module == module)
        if severity and "None" not in severity:
            q = q.filter(Insight.severity_label == severity)
        if ease and "None" not in ease:
            q = q.filter(Insight.ease_label == ease)
        if confidence and "None" not in confidence:
            q = q.filter(Insight.confidence_label == confidence)
        insights = q.order_by(Insight.date_added.desc()).limit(50).all()
    else:
        insights = Insight.query.filter(Insight.status == "open").order_by(Insight.date_added.desc()).limit(50).all()
    return render_template("insight.html",colors=colors,insights=insights,status=status,
        module=module,severity=severity,ease=ease,confidence=confidence)

@ui.route('/insight/close', methods = ['GET','POST'])
@roles_accepted('admin', 'manager')
def close_insight():
    id = request.form.get("insight_id")
    if id:
        insight = Insight.query.get(id)
        if insight:
            insight.status = "closed"
            db.session.commit()
            flash("Insight closed!",category="info")
            return redirect(url_for("main_ui.insight"))
    flash("ID not found!",category="warning")
    return redirect(url_for("main_ui.insight"))

@ui.route('/insight/<id>', methods = ['GET'])
@login_required
def view_insight(id):
    insight=Insight.query.get(id)
    return render_template("insight/view_insight.html",insight=insight)

@ui.route('/insight/stats', methods = ['GET'])
@login_required
def insight_stats():
    return render_template("insight/insight_stats.html")

@ui.route('/snapshot', methods = ['GET'])
@login_required
def snapshot():
    diff = request.args.get('diff', default = "month", type = str)
    data = RiskHelper().compare_recent_score_to_last_month()

    # Get stats
    insight_summary = RiskHelper().get_insight_summary_for_score()
    flash("Displaying the difference between current scores and last month",category="info")
    return render_template("snapshot.html",data=data,insight_summary=insight_summary)

@ui.route('/ledger/manage/software', methods = ['GET','POST'])
@roles_accepted('admin', 'manager')
def manage_software_ledger():
    if request.method == "POST":
        host_mapper = {
            "1":"server",
            "2":"workstation",
            "3":"all"
        }
        software = request.form.get("software")
        h_type = str(request.form.get("host_type","3"))
        host_type = host_mapper.get(h_type,"3")
        if software:
            if "add" in request.form:
                s = SoftwareLedger(name=software,host_type=host_type)
                db.session.add(s)
                db.session.commit()
                flash("Software added to ledger!",category="info")
            elif "remove" in request.form:
                s = SoftwareLedger.query.filter(SoftwareLedger.name == software).first()
                if s:
                    db.session.delete(s)
                    db.session.commit()
                    flash("Software removed from ledger!",category="info")
            return redirect(url_for("main_ui.manage_ledger"))
        flash("Missing software name!",category="warning")
        return redirect(url_for("main_ui.manage_ledger"))
    else:
        return redirect(url_for("main_ui.manage_ledger"))

@ui.route('/ledger/manage/assets', methods = ['GET','POST'])
@login_required
def manage_asset_ledger():
    if request.method == "POST":
        host_mapper = {
            "1":"user",
            "2":"group",
            "3":"computer"
        }
        asset = request.form.get("asset")
        o_class = str(request.form.get("objectclass","1"))
        objectclass = host_mapper.get(o_class,"1")
        if asset:
            if "add" in request.form:
                a = AssetLedger(name=asset,objectclass=objectclass)
                db.session.add(a)
                db.session.commit()
                flash("Asset added to ledger!",category="info")
            elif "remove" in request.form:
                a = AssetLedger.query.filter(AssetLedger.name == asset).first()
                if a:
                    db.session.delete(a)
                    db.session.commit()
                    flash("Asset removed from ledger!",category="info")
            return redirect(url_for("main_ui.manage_ledger"))
        flash("Missing asset name!",category="warning")
        return redirect(url_for("main_ui.manage_ledger"))
    else:
        return redirect(url_for("main_ui.manage_ledger"))

@ui.route('/ledger/manage', methods = ['GET','POST'])
@login_required
def manage_ledger():
    s_ledger = SoftwareLedger.query.all()
    a_ledger = AssetLedger.query.all()
    return render_template("settings/manage_ledger.html",s_ledger=s_ledger,a_ledger=a_ledger)

@ui.route('/settings/agent/<id>',methods = ['POST'])
@roles_accepted('admin', 'manager')
def agent_settings(id):
    agent = Agent.query.get(id)
    if agent:
        adc = request.form.get("adcollector")
        adv = request.form.get("advaulter")
        rtr = request.form.get("rtr")
        if adc:
            if "True" in adc:
                adc = 1
            else:
                adc = 0
            agent.adcollector = adc
        if adv:
            if "True" in adv:
                adv = 1
            else:
                adv = 0
            agent.advaulter = adv
        if rtr:
            if "True" in rtr:
                rtr = 1
            else:
                rtr = 0
            agent.rtr = rtr
        db.session.commit()
        return redirect(url_for("main_ui.manage_agents",id=id))
    flash("Agent does not exist.",category="warning")
    return redirect(url_for("main_ui.agents"))

@ui.route('/enable-ad-collector/<id>',methods = ['POST'])
@roles_accepted('admin', 'manager')
def enable_ad_collector(id):
    agent = Agent.query.get(id)
    if "enable" in request.form:
        agent.adcollector = 1
        db.session.commit()
    elif "disable" in request.form:
        agent.adcollector = 0
        db.session.commit()
    return redirect(url_for("main_ui.manage_agents",id=id))

@ui.route('/configuration', methods = ['GET'])
@login_required
def configuration():
    site = Site.query.first()
    return render_template("settings/configuration.html",site=site)

@ui.route('/users', methods = ['GET'])
@login_required
def users():
    return render_template("settings/users.html")

@ui.route('/users/manage/<id>', methods = ["GET","POST"])
@login_required
def manage_users(id):
    user = User.query.get(id)
    if user:
        return render_template("settings/manage_users.html",user=user,
            user_roles=user.roles,all_roles=Role.query.all())
    else:
        flash("User ID does not exist.",category="warning")
        return redirect(url_for("main_ui.users"))

@ui.route('/users/update/<id>', methods = ['POST'])
@roles_required("admin")
def update_user(id):
    user = User.query.get(id)
    if user:
        first = request.form.get("first")
        last = request.form.get("last")
        active = request.form.get("active")
        if first:
            user.first_name = first
        if last:
            user.last_name = last
        if active:
            if active.lower() == "true":
                user.active = True
            elif active.lower() == "false":
                user.active = False

        db.session.commit()
        flash("Updated user.")
        return redirect(url_for("main_ui.users"))
    flash("User does not exist.",category="warning")
    return redirect(url_for("main_ui.users"))

@ui.route('/users/delete/<id>', methods = ['POST'])
@roles_required("admin")
def delete_user(id):
    user = User.query.get(id)
    if user:
        if request.form.get("delete"):
            user.active = 0
            #db.session.delete(user)
            db.session.commit()
        flash("Deleted user.",category="warning")
        return redirect(url_for("main_ui.users"))
    flash("User does not exist.",category="warning")
    return redirect(url_for("main_ui.users"))

@ui.route('/users/roles/edit/<id>', methods = ['POST'])
@roles_required("admin")
def edit_user_roles(id):
    user = User.query.get(id)
    if user:
        role_id = request.form.get("role_id")
        if role_id:
            r = Role.query.get(role_id)
            if "add" in request.form:
                user.roles.append(r)
                flash("Role added to user.",category="info")
            elif "remove" in request.form:
                user.roles.remove(r)
                flash("Role removed from user.",category="warning")
            db.session.commit()
        return redirect(url_for("main_ui.users"))
    flash("User does not exist.",category="warning")
    return redirect(url_for("main_ui.users"))

@ui.route('/audit', methods = ['GET','POST'])
@login_required
def audit():
    return render_template("settings/audit.html")

@ui.route('/audit/manage/<id>', methods = ["GET","POST"])
@login_required
def manage_audit(id):
    key = AuditKey.query.get(id)
    return render_template("settings/manage_audit.html",key=key)

@ui.route('/audit/create', methods = ['GET','POST'])
@roles_accepted('admin', 'manager')
def create_audit():
    if request.method == "POST":
        template = {
            "keys":[]
        }
        posted_data = request.get_json()
        name = posted_data["name"]
        keys = posted_data["keys"]
        for key in keys:
            if key["enabled"] == "1":
                k = AuditKeyLedger.query.get(key["id"])
                if k:
                    template["keys"].append(k.full_path)
        a = AuditKey(name=name,data=template)
        db.session.add(a)
        db.session.commit()
        return "POST"
    else:
        keys = AuditKeyLedger.query.all()
        return render_template("settings/create_audit.html",keys=keys)

@ui.route('/audit/delete/<id>', methods = ['POST'])
@roles_accepted('admin', 'manager')
def delete_audit(id):
    if request.method == "POST":
        key = AuditKey.query.get(id)
        if key:
            db.session.delete(key)
            db.session.commit()
            flash("Audit removed",category="warning")
    return redirect(url_for("main_ui.audit"))

@ui.route('/ledger/auditkeys', methods = ['GET','POST'])
@login_required
def ledger_auditkeys():
    keys = AuditKeyLedger.query.all()
    return render_template("settings/ledger_auditkey.html",keys=keys)

@ui.route('/ledger/auditkeys/delete', methods = ['GET','POST'])
@roles_accepted('admin', 'manager')
def ledger_delete_auditkeys():
    if request.method == "POST":
        key_id = request.form["id"]
        a = AuditKeyLedger.query.get(key_id)
        if a:
            db.session.delete(a)
            db.session.commit()
            flash("Key removed from ledger.",category="warning")
    return redirect(url_for("main_ui.ledger_auditkeys"))

@ui.route('/ledger/auditkeys/create', methods = ['GET','POST'])
@roles_accepted('admin', 'manager')
def ledger_create_auditkeys():
    '''Add new run keys'''
    if request.method == "POST":
        title = request.form["title"]
        severity = request.form["severity"]
        path = request.form["path"]
        keyname = request.form["keyname"]
        value = request.form["value"]

        path = path.replace("/","\\")
        path = path.strip("\\")
        keyname = keyname.replace("/","\\")
        keyname = keyname.strip("\\")
        full_path = path+"\\"+keyname
        full_path = full_path.replace("\\","\\\\")

        a = AuditKeyLedger(title=title,hive="hklm",severity=severity,
            path=path,keyname=keyname,value=value,full_path=full_path)
        db.session.add(a)
        db.session.commit()
        flash("Key added to ledger.",category="info")
    return redirect(url_for("main_ui.ledger_auditkeys"))

@ui.route('/groups', methods = ['GET'])
@login_required
def groups():
    '''Agent Groups'''
    return render_template("settings/groups.html")

@ui.route('/groups/delete/<id>', methods = ['POST'])
@roles_accepted('admin', 'manager')
def delete_group(id):
    '''Delete group'''
    group = Group.query.get(id)
    if group:
        if request.form.get("delete"):
            db.session.delete(group)
            db.session.commit()
        flash("Deleted group.",category="info")
        return redirect(url_for("main_ui.groups"))
    flash("Group does not exist.",category="warning")
    return redirect(url_for("main_ui.groups"))

@ui.route('/groups/create', methods = ['GET','POST'])
@roles_accepted('admin', 'manager')
def create_group():
    '''Create new group'''
    if request.method == "POST":

        job_id = request.form.get("add_job")
        cmd_id = request.form.get("add_cmd")
        name = request.form.get("name")
        label = request.form.get("label")
        version = request.form.get("version")

        cmd = AgentCmd.query.get(cmd_id)
        job = Job.query.get(job_id)
        new_group = GroupOps(name).find_or_create_group(label,version,job,cmd,commit=True)
        flash("Group created..",category="info")
        return redirect(url_for("main_ui.groups"))
    else:
        commands = AgentCmd.query.all()
        jobs = Job.query.all()
        return render_template("settings/create_group.html",jobs=jobs,commands=commands)

@ui.route('/groups/version/update/<id>', methods = ['POST'])
@roles_accepted('admin', 'manager')
def update_group_version(id):
    group = Group.query.get(id)
    if group:
        new_version = request.form.get("version")
        if new_version:
            group.agentversion = new_version
            db.session.commit()
            flash("Minimum agent version for group has been updated.",category="info")
            return redirect(url_for("main_ui.groups"))
        flash("You must enter a version!",category="warning")
        return redirect(url_for("main_ui.groups"))
    flash("Group does not exist.",category="warning")
    return redirect(url_for("main_ui.groups"))

@ui.route('/groups/agent/update/<id>', methods = ['POST'])
@roles_accepted('admin', 'manager')
def update_group_agents(id):
    group = Group.query.get(id)
    if group:
        if request.form.get("update"):
            for agent in GroupOps(group.name).get_agents():
                agent.update = 1
                db.session.commit()
            flash("Agents in Group have been instructed to update.",category="info")
            return redirect(url_for("main_ui.groups"))
        flash("You must type update to proceed!",category="warning")
        return redirect(url_for("main_ui.groups"))
    flash("Group does not exist.",category="warning")
    return redirect(url_for("main_ui.groups"))

@ui.route('/groups/agent/edit/<id>', methods = ['POST'])
@roles_accepted('admin', 'manager')
def edit_group_agents(id):
    group = Group.query.get(id)
    aid = request.form.get("agent_id")
    agent = Agent.query.get(aid)
    if group and agent:
        if "add" in request.form:
            agent.groups.append(group)
            db.session.add(agent)
            db.session.commit()
            flash("Agent added to Group.",category="info")
        elif "remove" in request.form:
            agent.groups.remove(group)
            db.session.commit()
            flash("Agent removed from Group.",category="warning")
        return redirect(url_for("main_ui.groups"))
    flash("Group or Agent does not exist.",category="warning")
    return redirect(url_for("main_ui.groups"))

@ui.route('/groups/manage/<id>', methods = ['GET'])
@login_required
def manage_groups(id):
    group = Group.query.get(id)
    if group:
        old_agents = GroupOps(group.name).old_agents()
        # get agents
        agent_count=group.agents.count()
        jobs=group.job
        commands=group.cmd
        auditkey=group.akey
        if jobs and not isinstance(jobs,list):
            jobs=[jobs]
        if commands and not isinstance(commands,list):
            commands=[commands]
        if auditkey and not isinstance(auditkey,list):
            auditkey=[auditkey]
        return render_template("settings/manage_groups.html",id=id,name=group.name,agentversion=group.agentversion,
            old_agents=len(old_agents),agent_count=agent_count,jobs=jobs,commands=commands,auditkey=auditkey)
    else:
        flash("Group ID does not exist.",category="warning")
        return redirect(url_for("main_ui.groups"))

@ui.route('/groups/job/edit/<id>', methods = ['POST'])
@roles_accepted('admin', 'manager')
def edit_group_jobs(id):
    group = Group.query.get(id)
    job_id = request.form.get("job_id")
    job = Job.query.get(job_id)
    if group and job:
        if "add" in request.form:
            group.job = job
            db.session.commit()
            flash("Job added to Group.",category="info")
        elif "remove" in request.form:
            group.job = None
            db.session.commit()
            flash("Job removed from Group.",category="warning")
        return redirect(url_for("main_ui.groups"))
    flash("Group or Job does not exist.",category="warning")
    return redirect(url_for("main_ui.groups"))

@ui.route('/groups/command/edit/<id>', methods = ['POST'])
@roles_accepted('admin', 'manager')
def edit_group_commands(id):
    group = Group.query.get(id)
    cmd_id = request.form.get("command_id")
    cmd = AgentCmd.query.get(cmd_id)
    if group and cmd:
        if "add" in request.form:
            group.cmd = cmd
            db.session.commit()
            flash("Command added to Group.",category="info")
        elif "remove" in request.form:
            group.cmd = None
            db.session.commit()
            flash("Command removed from Group.",category="warning")
        return redirect(url_for("main_ui.groups"))
    flash("Group or Command does not exist.",category="warning")
    return redirect(url_for("main_ui.groups"))

@ui.route('/groups/auditkey/edit/<id>', methods = ['POST'])
@roles_accepted('admin', 'manager')
def edit_group_auditkey(id):
    group = Group.query.get(id)
    audit_id = request.form.get("auditkey_id")
    audit = AuditKey.query.get(audit_id)
    if group and audit:
        if "add" in request.form:
            group.akey = audit
            db.session.commit()
            flash("Audit added to Group.",category="info")
        elif "remove" in request.form:
            group.akey = None
            db.session.commit()
            flash("Audit removed from Group.",category="warning")
        return redirect(url_for("main_ui.groups"))
    flash("Group or Audit does not exist.",category="warning")
    return redirect(url_for("main_ui.groups"))

@ui.route('/jobs', methods = ['GET'])
@login_required
def jobs():
    '''Agent jobs'''
    return render_template("settings/jobs.html")

@ui.route('/jobs/create', methods = ['GET','POST'])
@roles_accepted('admin', 'manager')
def create_job():
    '''Create new job'''
    if request.method == "POST":
        posted_data = request.get_json()
        name = posted_data["name"]
        priority = posted_data["priority"]
        jobset = posted_data["jobset"]

        job = Job(name=name,priority=priority,data={"jobset":jobset})
        db.session.add(job)
        db.session.commit()
        return "POST"
    else:
        return render_template("settings/create_job.html",jobs=current_app.config["DEFAULT_JOB"])

@ui.route('/jobs/manage/<id>',methods = ['GET'])
@login_required
def manage_jobs(id):
    job = Job.query.get(id)
    if job:
        return render_template("settings/manage_jobs.html",job=job)
    else:
        flash("Job ID does not exist.",category="warning")
        return redirect(url_for("main_ui.jobs"))

@ui.route('/jobs/edit/<id>', methods = ['POST'])
@roles_accepted('admin', 'manager')
def edit_job(id):
    data = {"jobset":[]}
    posted_data = request.get_json()
    name = posted_data["name"]
    priority = int(posted_data["priority"])
    for task in posted_data["jobset"]:
        temp = {}
        for k,v in task.items():
            if k in ("force","enabled"):
                try:
                    v=int(v)
                    if v not in (0,1):
                        v=0
                except:
                    v=0
            if k in ("interval"):
                v=int(v)
            temp[k] = v
        data["jobset"].append(temp)
    job = Job.query.get(id)
    job.name = name
    job.priority = priority
    job.data = data
    db.session.commit()
    flash("Updated Job.",category="info")
    return jsonify({"message":"success"})

@ui.route('/jobs/delete/<id>', methods = ['POST'])
@roles_accepted('admin', 'manager')
def delete_job(id):
    job = Job.query.get(id)
    if job:
        if request.form.get("delete"):
            db.session.delete(job)
            db.session.commit()
        flash("Deleted job.",category="warning")
        return redirect(url_for("main_ui.jobs"))
    flash("Job does not exist.",category="warning")
    return redirect(url_for("main_ui.jobs"))

@ui.route('/agents/uninstall/<id>', methods = ['POST'])
@roles_accepted('admin', 'manager')
def uninstall_agent(id):
    agent = Agent.query.get(id)
    if agent:
        if request.form.get("uninstall"):
            agent.uninstall = 1
            db.session.commit()
            flash("Agent has been instructed to uninstall.",category="info")
            return redirect(url_for("agent_ui.agents"))
        flash("You must enter uninstall to proceed!",category="warning")
        return redirect(url_for("agent_ui.agents"))
    flash("Agent does not exist.",category="warning")
    return redirect(url_for("agent_ui.agents"))

@ui.route('/agents/manage/<id>', methods = ['GET'])
@login_required
def manage_agents(id):
    '''Manage Agent'''
    agent = Agent.query.get(id)
    if agent:
        agent = Agent.query.get(id)
        adcollector="False"
        advaulter="False"
        if agent.adcollector:
            adcollector="True"
        if agent.advaulter:
            advaulter="True"
        uninstall="False"
        if agent.uninstall:
            uninstall="True"

        check_in = None
        if agent.last_active:
            temp = (datetime.now() - agent.last_active).total_seconds() / 60.0
            check_in = "{0:.2f}".format(temp)

        jobs = AgentOps(id).get_job()
        groups = AgentOps(id).get_groups()
        commands = AgentOps(id).get_cmd()
        return render_template("settings/manage_agents.html",id=id,agent=agent,name=agent.fqdn,
            version=agent.version,uninstall=uninstall,adcollector=adcollector,advaulter=advaulter,active=check_in,
            commands=commands,jobs=jobs,groups=groups)
    flash("Agent does not exist.",category="warning")
    return redirect(url_for("main_ui.agents"))

@ui.route('/commands', methods = ['GET'])
@login_required
def commands():
    '''Agent commands'''
    return render_template("settings/commands.html")

@ui.route('/commands/create', methods = ['GET','POST'])
@roles_accepted('admin', 'manager')
def create_command():
    '''Create new command'''
    data = {"commands":[]}
    if request.method == "POST":
        name = request.form.get("name")
        priority = request.form.get("priority")
        commands = request.form.get("commands")
        for cmd in commands.split(","):
            data["commands"].append({"cmd":cmd})
        cmd = AgentCmd(name=name,priority=priority,data=data)
        db.session.add(cmd)
        db.session.commit()
        return "POST"
    else:
        return render_template("settings/create_command.html",command=current_app.config["DEFAULT_CMD"])

@ui.route('/commands/manage/<id>', methods = ['GET'])
@login_required
def manage_commands(id):
    command = AgentCmd.query.get(id)
    if command:
        return render_template("settings/manage_commands.html",command=command)
    else:
        flash("Command ID does not exist.",category="warning")
        return redirect(url_for("main_ui.commands"))

@ui.route('/commands/edit/<id>', methods = ['POST'])
@roles_accepted('admin', 'manager')
def edit_commands(id):
    command = AgentCmd.query.get(id)
    if command:
        priority = request.form.get("priority")
        add_cmd = request.form.get("add_cmd")
        remove_cmd = request.form.get("remove_cmd")

        data = {"commands":[]}
        current_cmds = []
        for cmd in command.data["commands"]:
            current_cmds.append(cmd["cmd"])
        if add_cmd and add_cmd.lower() not in current_cmds:
            current_cmds.append(add_cmd.lower())
        if remove_cmd:
            current_cmds.remove(remove_cmd.lower())
        for cmd in current_cmds:
            data["commands"].append({"cmd":cmd.lower()})

        command.data = data
        command.priority = priority
        db.session.commit()
        flash("Edited command.", category="info")
        return redirect(url_for("main_ui.manage_commands",id=id))
    flash("Command does not exist.",category="warning")
    return redirect(url_for("main_ui.commands"))

@ui.route('/commands/delete/<id>', methods = ['POST'])
@roles_accepted('admin', 'manager')
def delete_command(id):
    command = AgentCmd.query.get(id)
    if command:
        if request.form.get("delete"):
            db.session.delete(command)
            db.session.commit()
        flash("Deleted command.",category="warning")
        return redirect(url_for("main_ui.commands"))
    flash("Command does not exist.",category="warning")
    return redirect(url_for("main_ui.commands"))

@ui.route('/whitelist', methods = ['GET'])
@login_required
def whitelist():
    return render_template("settings/whitelist.html")

@ui.route('/blacklist', methods = ['GET'])
@login_required
def blacklist():
    return render_template("settings/blacklist.html")

#//''' ### Error Handling ### '''
@ui.errorhandler(401)
def unauthenticated(error):
    return jsonify({"message":str(error)})

@ui.errorhandler(403)
def unauthorized(error):
    return jsonify({"message":str(error)})

@ui.errorhandler(404)
def page_not_found(error):
    return render_template('httpcodes/404.html'), 404

@ui.errorhandler(500)
def internal_error(error):
    return render_template('httpcodes/500.html'), 500
