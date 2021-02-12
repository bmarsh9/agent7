from flask import Flask, abort, request, jsonify, url_for, render_template,redirect, session, flash, current_app
from app import db
from app.models import AgentInteract,Agent,Group,ADGroup
from random import choice
from string import digits
from flask_wtf import Form
from wtforms.fields import DateField
from datetime import datetime,timedelta
from app.agent import ui
from app.utils.db_helper import DynamicQuery
from app.utils.ad_helper import ADHelper
from app.utils.decorators import login_required, roles_required,current_user,roles_accepted
import json
import uuid

@ui.route("/agent/health")
@login_required
def agent_health():
    return render_template("settings/health.html")

@ui.route("/rtr")
@roles_required('rtr')
def rtr_home():
    '''home page for rtr'''
    return render_template("agent/rtr_home.html")

@ui.route("/rtr/campaign", methods = ['GET','POST'])
@roles_required('rtr')
def rtr_campaign():
    '''run scripts for groups in rtr'''
    if request.method == "GET":
        data = []
        for group in Group.query.all():
            data.append({"id":group.id,"name":group.name,"count":group.agents.count()})
        return render_template("agent/rtr_campaign.html",data=data)
    else:
        command = request.form.get("command")
        group_id = request.form.get("group")
        group = Group.query.get(group_id)
        if not command:
            flash("Command is mandatory!",category="warning")
            return redirect(url_for("agent_ui.rtr_campaign"))
        if group:
            # add command to each agent in group
            session = "campaign_{}_{}".format(datetime.now().strftime("%m-%d-%Y"),uuid.uuid4().hex[:6])
            for agent in group.agents.all():
                c = AgentInteract(campaign=True,cmd=command,session=session,username=current_user.email,host_id=agent.id)
                db.session.add(c)
            db.session.commit()
            flash("Campaign successfully started. Please check back for the results: {}".format(session),category="info")
            return redirect(url_for("agent_ui.rtr_campaign"))

        flash("Group ID not found!",category="warning")
        return redirect(url_for("agent_ui.rtr_campaign"))

@ui.route("/rtr/audit/<id>")
@roles_accepted("admin","manager")
def rtr_view_audit(id):
    session = AgentInteract.query.get(id)
    if session:
        return render_template("agent/rtr_review.html",name=session.session,cmd=session.cmd)
    return redirect(url_for("agent_ui.rtr_audit"))

@ui.route("/rtr/audit")
@roles_required('rtr')
def rtr_audit(id=None):
    '''view audit for rtr'''
    return render_template("agent/rtr_audit.html")

@ui.route("/rtr/shell", methods = ['GET'])
@roles_required('rtr')
def rtr_shell():
    '''shell access for rtr'''
    aid = request.args.get('agent')
    agent = Agent.query.filter(Agent.id == aid).first()
    if agent:
        if not agent.rtr:
            flash("RTR is not enabled for this agent. Please enable it below.",category="warning")
            return redirect(url_for("agent_ui.rtr_home"))
        checkin_time = 2 # minutes
        since = datetime.now() - timedelta(minutes=checkin_time)
        agent = Agent.query.filter(Agent.last_active > since).filter(Agent.id == aid).first()
        if agent:
            session = "{}_{}".format(datetime.now().strftime("%m-%d-%Y"),uuid.uuid4().hex[:6])
            return render_template("agent/rtr_interact.html",agent=agent,session=session,date_started=datetime.now())
        else:
            flash("Agent is not online (within:{} minutes) or does not exist!".format(checkin_time),category="warning")
            return redirect(url_for("agent_ui.rtr_home"))
    flash("Agent ID does not exist!",category="warning")
    return redirect(url_for("agent_ui.rtr_home"))

@ui.route('/panel', methods = ['GET'])
@ui.route('/panels', methods = ['GET'])
@ui.route('/panel/ep', methods = ['GET'])
@login_required
def panels():
    return render_template("agent/panels.html")

@ui.route('/panel/ep/users', methods = ['GET'])
@login_required
def local_users():
    return render_template("agent/local_users.html")

@ui.route('/panel/ep/auditkeys', methods = ['GET'])
@login_required
def auditkeys():
    return render_template("agent/auditkeys.html")

@ui.route('/panel/ep/printers', methods = ['GET'])
@login_required
def printers():
    return render_template("agent/printers.html")

@ui.route('/panel/ep/fleet', methods = ['GET'])
@login_required
def fleet():
    return render_template("agent/fleet.html")

@ui.route('/panel/ep/pipes', methods = ['GET'])
@login_required
def pipes():
    return render_template("agent/pipes.html")

@ui.route('/panel/ep/groups', methods = ['GET'])
@login_required
def local_groups():
    return render_template("agent/local_groups.html")

@ui.route('/panel/ep/disk_memory', methods = ['GET'])
@login_required
def disk_memory():
    return render_template("agent/disk_and_memory.html")

@ui.route('/panel/ep/startup', methods = ['GET'])
@login_required
def startup():
    checked = request.args.get("priv_view",default="*",type=str)
    return render_template("agent/startup.html",checked=checked)

@ui.route('/panel/ep/schtask', methods = ['GET'])
@login_required
def schtask():
    checked = request.args.get("priv_view",default="*",type=str)
    return render_template("agent/schtask.html",checked=checked)

@ui.route('/panel/ep/netadapter', methods = ['GET'])
@login_required
def netadapter():
    return render_template("agent/netadapter.html")

@ui.route('/panel/ep/share', methods = ['GET'])
@login_required
def share():
    return render_template("agent/share.html")

@ui.route('/panel/ep/profile', methods = ['GET'])
@login_required
def profile():
    return render_template("agent/profile.html")

@ui.route('/panel/ep/logon', methods = ['GET'])
@login_required
def logon():
    checked = request.args.get("priv_view",default="*",type=str)
    return render_template("agent/logon.html",checked=checked)

@ui.route('/panel/ep/updates', methods = ['GET'])
@login_required
def updates():
    return render_template("agent/updates.html")

@ui.route('/panel/ep/patch', methods = ['GET'])
@login_required
def patch():
    return render_template("agent/patch.html")

@ui.route('/panel/ep/system', methods = ['GET'])
@login_required
def system():
    return render_template("agent/system.html")

@ui.route('/panel/ep/service', methods = ['GET'])
@login_required
def service():
    checked = request.args.get("priv_view",default="*",type=str)
    return render_template("agent/service.html",checked=checked)

@ui.route('/panel/ep/netconnect', methods = ['GET'])
@login_required
def connections():
    checked = request.args.get("priv_view",default="*",type=str)
    return render_template("agent/netconnect.html",checked=checked)

@ui.route('/panel/ep/software', methods = ['GET'])
@login_required
def software():
    return render_template("agent/software.html")

@ui.route('/agents', methods = ['GET'])
@login_required
def agents():
    return render_template("agent/agents.html")

#------------- Active Directory -------------------
@ui.route('/panel/ad', methods = ['GET'])
@login_required
def ad_panels():
    return render_template("agent/ad_panels.html")

@ui.route('/panel/ad/users', methods = ['GET'])
@login_required
def ad_users():
    return render_template("agent/ad_users.html")

@ui.route('/panel/ad/groups', methods = ['GET'])
@login_required
def ad_groups():
    return render_template("agent/ad_groups.html")

@ui.route('/panel/ad/groupmembers/<sid>', methods = ['GET'])
@login_required
def ad_group_members(sid):
    group = ADGroup.query.filter(ADGroup.objectsid == sid).order_by(ADGroup.id.desc()).first()
    if not group:
        flash("Group SID not found!",category="warning")
        return redirect(url_for("agent_ui.ad_groups"))
    return render_template("agent/ad_group_member.html",group=group)

@ui.route('/panel/ad/computers', methods = ['GET'])
@login_required
def ad_computers():
    return render_template("agent/ad_computers.html")

@ui.route('/panel/ad/domains', methods = ['GET'])
@login_required
def ad_domains():
    return render_template("agent/ad_domain.html")

@ui.route('/panel/ad/ous', methods = ['GET'])
@login_required
def ad_ous():
    return render_template("agent/ad_ous.html")

@ui.route('/panel/ad/spn', methods = ['GET'])
@login_required
def ad_spns():
    all_spn = ADHelper().get_all_spn_metrics()
    spn_count = len(all_spn)
    return render_template("ad/spn_viewer.html",spn=all_spn,spn_count=spn_count)

@ui.route('/panel/ad/spn/<string:service>', methods = ['GET'])
@login_required
def ad_spn_service(service):
    data = ADHelper().hosts_with_spn(service)
    return render_template("ad/spn_view_service.html",data=data)

@ui.route('/panel/ad/privileged/users', methods = ['GET'])
@login_required
def ad_priv_users():
    users = ADHelper().get_priv_users_format_1()
    stale_accounts = []
    stale_passwords = []
    easy_fixes = []
    medium_risk = []
    high_risk = []
    critical_risk = []
    # no recent login
    for user in users:
        if user["active"] == "no":
            stale_accounts.append(user)
        if user["last_pwd_change"] >= 720:
            stale_passwords.append(user)
        if user["last_logon"] >= 120:
            easy_fixes.append(user)
        if user["require_preauth"] == "no" or user["delegation"] == "yes" or user["des_key_only"] == "yes" or user["password_encrypted"] == "no" or user["roastable"] == "yes":
            medium_risk.append(user)
        if user["last_pwd_change"] >= 1820 and user["require_preauth"] == "no" or user["delegation"] == "yes" or user["des_key_only"] == "yes" or user["password_encrypted"] == "no":
            high_risk.append(user)
        if user["last_pwd_change"] >= 1820 and user["roastable"] == "yes":
            critical_risk.append(user)
    return render_template("ad/privileged_users.html",users=len(users),
        stale_accounts=stale_accounts,stale_passwords=stale_passwords,
        easy_fixes=easy_fixes,medium_risk=medium_risk,high_risk=high_risk,critical_risk=critical_risk)

#----------------- Web UI --------------------#
@ui.route("/explore")
@login_required
def explore():
    return render_template("agent/explore.html")

'''
@ui.route("/")
@login_required
def dashboard():
    # Geo IP data
    data = []
    for agent in db.session.query(Agent).distinct(Agent.city_name).limit(50).all():
        data.append({"code":agent.country_code,"city":agent.city_name,"country":agent.country_name,"lat":agent.lat,"lon":agent.long})

    # Risk score data
    risk_data = RiskHelper(days_ago=364,limit=7).get_timeline_risk()
    compare_data = RiskHelper().get_comparison_risk()

    # Get current risk
    current_risk = RiskHelper().get_recent_total_risk()
    return render_template("agent/dashboard.html",data=json.dumps(data),risk_data=risk_data,compare_data=compare_data,current_risk=current_risk)
    return render_template("dashboard.html",data=json.dumps(data))
'''
