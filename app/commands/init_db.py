import datetime
from flask import current_app
from flask_script import Command
import uuid
from app import db
from app.utils.operations import AgentOps, GroupOps, JobOps, AgentCmdOps
from app.models import User, Role,Group, Agent, Site, AgentSoftware, Job, AgentCmd,IpLocation,AssetLedger,AuditKeyLedger,ComparisonScore,RiskScore
from sqlalchemy import create_engine
import os
import json

class InitDbCommand(Command):
    """ Initialize the database."""

    def run(self):
        init_db()
        print('Database has been initialized.')

def init_db():
    """ Initialize the database."""
    db.drop_all()
    db.create_all()
    create_site()
    create_users()
    create_agent_tasks()
    create_auditkeys()

def create_auditkeys():
    file_name = os.path.join(current_app.config["INITDBDIR"],"auditkeys_ledger.json")
    if os.path.isfile(file_name):
        with open(file_name, 'r') as f:
            runkeys = json.load(f)
            for key in runkeys:
                a = AuditKeyLedger(**key)
                db.session.add(a)
            db.session.commit()

def create_site():
    db.create_all()
    site = find_or_create_site(key=current_app.config["SITE_KEY"])

    # Save to DB
    db.session.commit()

def create_users():
    """ Create users """

    # Create all tables
    db.create_all()

    # Adding roles
    admin_role = find_or_create_role('admin', u'Admin')
    manager_role = find_or_create_role('manager', u'Manager')
    rtr_role = find_or_create_role('rtr', u'RTR')

    # Add default user
    user = find_or_create_user(u'Admin', u'Example', u'admin@example.com', 'Password1', admin_role)

    # Save to DB
    db.session.commit()

def create_agent_tasks():
    default_cmd = AgentCmdOps("default_cmd").find_or_create_agentcmd(current_app.config["DEFAULT_CMD"],10)
    default_job = JobOps("default_job").find_or_create_job(current_app.config["DEFAULT_JOB"],10)
    default_group = GroupOps("default").find_or_create_group("Default","1.0.0",default_job,default_cmd,commit=True)

def find_or_create_role(name, label):
    """ Find existing role or create new role """
    role = Role.query.filter(Role.name == name).first()
    if not role:
        role = Role(name=name, label=label)
        db.session.add(role)
    return role

def find_or_create_user(first_name, last_name, email, password, role=None):
    """ Find existing user or create new user """
    user = User.query.filter(User.email == email).first()
    if not user:
        user = User(email=email,
                    first_name=first_name,
                    last_name=last_name,
                    password=current_app.user_manager.password_manager.hash_password(password),
                    active=True,
                    email_confirmed_at=datetime.datetime.utcnow())
        if role:
            user.roles.append(role)
        db.session.add(user)
    return user

def find_or_create_group(name, label, job_data=None, cmd_data=None,commit=False):
    '''Add Group'''
    group = Group.query.filter(Group.name == name).first()
    if not group:
        group = Group(name=name, label=label)
    if job_data:
        group.job = job_data
    if cmd_data:
        group.cmd = cmd_data
    db.session.add(group)
    if commit:
        db.session.commit()
    return group

def find_or_create_job(name, data,priority):
    """ Find existing job or create new job """
    job = Job.query.filter(Job.name == name).first()
    if not job:
        job = Job(name=name, data=data,priority=priority)
        db.session.add(job)
    return job

def find_or_create_agentcmd(name, data,priority):
    """ Find existing agentcmd or create new agentcmd """
    agentcmd = AgentCmd.query.filter(AgentCmd.name == name).first()
    if not agentcmd:
        agentcmd = AgentCmd(name=name, data=data,priority=priority)
        db.session.add(agentcmd)
    return agentcmd

def find_or_create_agent(id, hostname, group=None):
    """ Find existing agent or create new agent """
    agent = Agent.query.filter(Agent.id == id).first()
    if not agent:
        agent = Agent(id=id,
                    hostname=hostname)
        if group:
            agent.groups.append(group)
        db.session.add(agent)
    return agent

def find_or_create_site(key=None):
    """ Find existing site or create new site """
    if not key:
        key = uuid.uuid4()
    site = Site.query.filter(Site.key == key,).first()
    if not site:
        site = Site(key=key,console_version=current_app.config["CONSOLE_VERSION"],license=current_app.config["LICENSE"])
        db.session.add(site)
    return site
