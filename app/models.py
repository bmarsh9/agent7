from flask import current_app
from sqlalchemy.sql import func,text
from sqlalchemy.dialects.postgresql import JSON,JSONB
from sqlalchemy import asc,desc,orm
import json,os,uuid
from time import time
import datetime
from datetime import timedelta
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from app import db
from app.utils.formatmsg import msg_to_json

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, validators
from flask_user import UserMixin
from app.utils.mixins import AgentMixin
import base64
import arrow

class Tasks(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    name = db.Column(db.String(64), unique=True)
    description = db.Column(db.String())
    enabled = db.Column(db.Boolean, default=True)
    module = db.Column(db.String())
    healthy = db.Column(db.Boolean, default=True)
    args = db.Column(db.JSON(),default={})
    start_on = db.Column(db.DateTime)
    last_ran = db.Column(db.DateTime)
    run_every = db.Column(db.Integer,default="10") # in minutes
    date_added = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.datetime.utcnow)

    def pretty_dt(self,date):
        return arrow.get(date).format("MMM D, HH:mm A")

    @staticmethod
    def ready_to_run():
        tasks = []
        now = arrow.utcnow()
        enabled_tasks = Tasks.query.filter(Tasks.enabled == True).all()
        for task in enabled_tasks:
            if task.module:
                if not task.last_ran: # never ran
                    if not task.start_on or now > arrow.get(task.start_on):
                        tasks.append(task)
                else:
                    minutes = task.run_every or 1
                    if arrow.get(task.last_ran).shift(minutes=minutes) < now:
                        tasks.append(task)
        return tasks

    def was_executed(self):
        now = arrow.utcnow().datetime
        self.last_ran = now
        db.session.commit()

    def get_next_run(self,humanize=False):
        minutes = self.run_every or 0
        if self.last_ran:
            next_run = arrow.get(self.last_ran).shift(minutes=minutes or 1)
        else:
            next_run = arrow.utcnow()
        if humanize:
            return next_run.humanize()
        return next_run

class ComparisonScore(db.Model):
    '''Table for holding comparison score data such as industry or other clients'''
    __tablename__ = 'comparison_score'
    id = db.Column(db.Integer, primary_key=True)
    agent_risk = db.Column(db.Integer)
    ad_risk = db.Column(db.Integer)
    watcher_risk = db.Column(db.Integer)
    total_risk = db.Column(db.Integer)
    grade = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())

class RiskScore(db.Model):
    __tablename__ = 'risk_score'
    id = db.Column(db.Integer, primary_key=True)
    agent_risk = db.Column(db.Integer)
    ad_risk = db.Column(db.Integer)
    watcher_risk = db.Column(db.Integer)
    total_risk = db.Column(db.Integer)
    grade = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    # Ref
    insights = db.relationship("Insight",backref="riskscore", lazy="dynamic")

class Insight(db.Model):
    __tablename__ = 'insight'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String())
    description = db.Column(db.String())
    category = db.Column(db.String()) # availability, hardening, anomaly
    solution = db.Column(db.String())
    confidence_label = db.Column(db.String())
    severity_label = db.Column(db.String())
    ease_label = db.Column(db.String())
    severity = db.Column(db.Integer)
    ease = db.Column(db.Integer)
    confidence = db.Column(db.Integer)
    data = db.Column(db.JSON())
    hits = db.Column(db.Integer)
    affected_assets = db.Column(db.Integer)
    risk = db.Column(db.Integer)
    assets = db.Column(db.JSON())
    module = db.Column(db.String())
    phase_one = db.Column(db.String())
    phase_two = db.Column(db.String())
    phase_three = db.Column(db.String())
    status = db.Column(db.String(),server_default="open") # open, in progress, closed
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    # Ref
    riskscore_id = db.Column(db.Integer, db.ForeignKey('risk_score.id'), nullable=False)

class SoftwareLedger(db.Model):
    __tablename__ = 'software_ledger'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String())
    approved = db.Column(db.Boolean,server_default='1')
    host_type = db.Column(db.String()) # workstation,server,all
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())

class AssetLedger(db.Model):
    __tablename__ = 'asset_ledger'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String())
    objectclass = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())

#----------------------------------- Settings Database
class IpLocation(db.Model):
    '''
    Class for IP Location
    '''
    __tablename__ = 'iplocation'
    ip_from = db.Column(db.BigInteger,primary_key=True)
    ip_to = db.Column(db.BigInteger,primary_key=True)
    country_code = db.Column(db.String())
    country_name = db.Column(db.String())
    region_name = db.Column(db.String())
    city_name = db.Column(db.String())
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)

class Whitelist(db.Model):
    '''
    Class for Whitelist
    '''
    __tablename__ = 'whitelist'
    id = db.Column(db.Integer, primary_key=True)
    datatype = db.Column(db.String())
    datavalue = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    enabled = db.Column(db.Boolean,server_default='1')

class Blacklist(db.Model):
    '''
    Class for Blacklist
    '''
    __tablename__ = 'blacklist'
    id = db.Column(db.Integer, primary_key=True)
    datatype = db.Column(db.String())
    datavalue = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    enabled = db.Column(db.Boolean,server_default='1')

class Site(db.Model):
    '''
    Class for Site
    '''
    __tablename__ = 'site'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String,  default=lambda: str(uuid.uuid4()), unique=True)
    remove_stale_agents = db.Column(db.Boolean, default=False)
    console_version = db.Column(db.String())
    license = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())

class Agent(db.Model):
    __tablename__ = "agent"
    id = db.Column(db.Integer, primary_key=True,autoincrement=False)
    token = db.Column(db.String,  default=lambda: str(uuid.uuid4()), unique=True)
    version = db.Column(db.String())
    major = db.Column(db.Integer)
    minor = db.Column(db.Integer)
    fix = db.Column(db.Integer)
    install_group = db.Column(db.String())
    console = db.Column(db.String())
    public_addr = db.Column(db.String)
    country_code = db.Column(db.String())
    country_name = db.Column(db.String())
    region_name = db.Column(db.String())
    city_name = db.Column(db.String())
    lat = db.Column(db.Float)
    long = db.Column(db.Float)
    update = db.Column(db.Integer, server_default='0')
    uninstall = db.Column(db.Integer, server_default='0')
    adcollector = db.Column(db.Integer, server_default='0')
    advaulter = db.Column(db.Integer, server_default='0')
    rtr = db.Column(db.Integer, server_default='0')
    #// Base
    hostname = db.Column(db.String())
    fqdn = db.Column(db.String())
    domain = db.Column(db.String())
    forest = db.Column(db.String())
    dn = db.Column(db.String())
    site = db.Column(db.String())
    domain_joined = db.Column(db.Boolean)
    is_dc = db.Column(db.Boolean)
    family = db.Column(db.String()) #windows
    release = db.Column(db.String()) #10
    sysversion = db.Column(db.String()) #1903
    installtype = db.Column(db.String())
    edition = db.Column(db.String())
    build = db.Column(db.String())
    machine = db.Column(db.String()) #amd64
    local_addr = db.Column(db.String())
    memory = db.Column(db.String())
    cpu = db.Column(db.String())
    processor = db.Column(db.String())
    last_boot = db.Column(db.DateTime)
    last_active = db.Column(db.DateTime)
    enabled = db.Column(db.Boolean, server_default='1')
    status = db.Column(db.String())
    errors = db.Column(db.Integer)
    cmd = db.Column(db.String()) # interactive commands
    svc_start = db.Column(db.DateTime)
    svc_uptime = db.Column(db.Integer)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Compliance
    compliance_grade = db.Column(db.String())
    total_compliance_checks = db.Column(db.Integer)
    compliant = db.Column(db.Integer)
    non_compliant = db.Column(db.Integer)
    percentage_compliant = db.Column(db.Integer)

    #// Ref
    groups = db.relationship('Group', secondary='agents_groups',
                            backref=db.backref('agents', lazy='dynamic'))

# Define the Group data model
class Group(db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), nullable=False, server_default=u'', unique=True)  # for @roles_accepted()
    agentversion = db.Column(db.String(50))
    label = db.Column(db.String(255), server_default=u'')  # for display purposes
    # Relationships
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'))
    cmd_id = db.Column(db.Integer, db.ForeignKey('agentcmd.id'))
    akey_id = db.Column(db.Integer, db.ForeignKey('auditkey.id'))

class Job(db.Model):
    __tablename__ = 'job'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), nullable=False, server_default=u'', unique=True)
    data = db.Column(db.JSON())
    priority = db.Column(db.Integer(), default=10)
    #// Ref
    group = db.relationship('Group', backref='job')

class AgentCmd(db.Model):
    __tablename__ = 'agentcmd'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), nullable=False, server_default=u'', unique=True)
    data = db.Column(db.JSON)
    priority = db.Column(db.Integer(), default=10)
    #// Ref
    group = db.relationship('Group', backref='cmd')

class AuditKey(db.Model):
    __tablename__ = 'auditkey'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), nullable=False, server_default=u'', unique=True)
    data = db.Column(db.JSON)
    #// Ref
    group = db.relationship('Group', backref='akey')

class AuditKeyLedger(db.Model):
    __tablename__ = 'auditkeyledger'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(),nullable=False)
    platform = db.Column(db.String())
    hive = db.Column(db.String())
    path = db.Column(db.String(),nullable=False)
    full_path = db.Column(db.String(),nullable=False,unique=True)
    keyname = db.Column(db.String(),nullable=False)
    value = db.Column(db.String())
    severity = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())

# Define the AgentGroups association model
class AgentsGroups(db.Model):
    __tablename__ = 'agents_groups'
    id = db.Column(db.Integer(), primary_key=True)
    agent_id = db.Column(db.Integer(), db.ForeignKey('agent.id', ondelete='CASCADE'))
    group_id = db.Column(db.Integer(), db.ForeignKey('groups.id', ondelete='CASCADE'))
    #job_id = db.Column(db.Integer(), db.ForeignKey('job.id', ondelete='CASCADE'))

# Define the User data model. Make sure to add the flask_user.UserMixin !!
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)

    # User authentication information (required for Flask-User)
    email = db.Column(db.Unicode(255), nullable=False, server_default=u'', unique=True)
    email_confirmed_at = db.Column(db.DateTime())
    password = db.Column(db.String(255), nullable=False, server_default='')
    active = db.Column(db.Boolean(), nullable=False, server_default='0')

    # User information
    active = db.Column('is_active', db.Boolean(), nullable=False, server_default='0')
    first_name = db.Column(db.Unicode(50), nullable=False, server_default=u'')
    last_name = db.Column(db.Unicode(50), nullable=False, server_default=u'')

    # Relationships
    roles = db.relationship('Role', secondary='users_roles',
                            backref=db.backref('users', lazy='dynamic'))

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None # valid token, but expired
        except BadSignature:
            return None # invalid token
        user = User.query.get(data['id'])
        return user

    def generate_auth_token(self, expiration = 6000):
        s = Serializer(current_app.config['SECRET_KEY'], expires_in = expiration)
        return s.dumps({ 'id': self.id })

# Define the Role data model
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), nullable=False, server_default=u'', unique=True)  # for @roles_accepted()
    label = db.Column(db.Unicode(255), server_default=u'')  # for display purposes


# Define the UserRoles association model
class UsersRoles(db.Model):
    __tablename__ = 'users_roles'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('roles.id', ondelete='CASCADE'))

class UserInvitation(db.Model):
    __tablename__ = 'user_invitations'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    invited_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

class AuditLogs(db.Model):
    '''
    Database class for audit logs
    Available levels:
        .info -> General information
        .warning -> Warnings
        .alert -> Security alerts
        .errors -> Exceptions caught
    '''
    __tablename__ = 'auditlogs'
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String())
    level = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    user_id = db.Column(db.Integer)

    @staticmethod
    def add(self,**kwargs):
        db.session.add(**kwargs)
        db.session.commit()

def get_TableSchema(table,column=None,is_date=False,is_int=False,is_str=False,is_json=False,is_bool=False):
    '''
    :Description - Get a tables col names and types
    :Usage - ("table",column="message",is_str=True)
    '''
    data = {}
    for col in table.__table__.columns:
        try: # field type JSON does not have a type attribute
            col_type=str(col.type)
        except:
            col_type="JSON"
        data[col.name] = str(col_type)
    if column is not None:
        splice = data.get(column,None)
        if splice:
            if is_int and "INTEGER" in splice:
                return True
            if is_str and "VARCHAR" in splice:
                return True
            if is_json and "JSON" in splice:
                return True
            if is_bool and "BOOLEAN" in splice:
                return True
            if is_date and "DATETIME" in splice:
                return True
            return False
        raise Exception("Column not found")
    return data

class AgentAuditKey(db.Model):
    __tablename__ = 'agentauditkey'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String())
    severity = db.Column(db.String())
    key = db.Column(db.String())
    value = db.Column(db.String())
    compliant_value = db.Column(db.String())
    compliant = db.Column(db.String())
    host_name = db.Column(db.String())
#    results = db.Column(db.JSON)
#    total = db.Column(db.Integer)
#    compliant = db.Column(db.Integer)
#    non_compliant = db.Column(db.Integer)
#    percentage_compliant = db.Column(db.Integer)
#    grade = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    message_id = db.Column(db.String())

class AgentNeighbor(db.Model):
    __tablename__ = "agentneighbor"
    id = db.Column(db.Integer, primary_key=True)
    asset = db.Column(db.String())
    address = db.Column(db.String())
    mac = db.Column(db.String())
    type = db.Column(db.String())
    status = db.Column(db.String())
    ports = db.relationship('NeighborPort', backref='neighbor', lazy='dynamic')
    host_name = db.Column(db.String())    
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    message_id = db.Column(db.String())    

class NeighborPort(db.Model):
    __tablename__ = "neighborport"
    id = db.Column(db.Integer, primary_key=True)
    port = db.Column(db.Integer)
    service = db.Column(db.String())
    neighbor_id = db.Column(db.Integer, db.ForeignKey('agentneighbor.id'))
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    message_id = db.Column(db.String()) 
    
class AgentMemory(db.Model):
    __tablename__ = "agentmemory"
    id = db.Column(db.Integer, primary_key=True)
    used = db.Column(db.String())
    cache = db.Column(db.String())
    free = db.Column(db.String())
    shared = db.Column(db.String())
    host_name = db.Column(db.String())
    total = db.Column(db.String())
    buffers = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    message_id = db.Column(db.String())

class AgentPrinter(db.Model):
    __tablename__ = "agentprinter"
    id = db.Column(db.Integer, primary_key=True)
    flags = db.Column(db.String())
    status = db.Column(db.String())
    description = db.Column(db.String())
    name = db.Column(db.String())
    host_name = db.Column(db.String())
    path = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    message_id = db.Column(db.String())

class AgentDisk(db.Model):
    __tablename__ = "agentdisk"
    id = db.Column(db.Integer, primary_key=True)
    used_percent = db.Column(db.Integer)
    used = db.Column(db.String())
    mount = db.Column(db.String())
    free = db.Column(db.String())
    fs_type = db.Column(db.String())
    host_name = db.Column(db.String())
    device = db.Column(db.String())
    total = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    message_id = db.Column(db.String())

class AgentSchTask(db.Model):
    __tablename__ = "agentschtask"
    id = db.Column(db.Integer, primary_key=True)
    host_name = db.Column(db.String())
    last_result = db.Column(db.String())
    folder = db.Column(db.String())
    hidden = db.Column(db.Boolean)
    state = db.Column(db.String())
    last_run = db.Column(db.DateTime)
    enabled = db.Column(db.Boolean)
    next_run = db.Column(db.DateTime)
    sid = db.Column(db.String())
    username = db.Column(db.String())
    domain = db.Column(db.String())
    account_type = db.Column(db.String())
    hash = db.Column(db.String())
    command = db.Column(db.String())
    base_command = db.Column(db.String())
    image = db.Column(db.String())
    arguments = db.Column(db.String())
    run_level = db.Column(db.String())
    is_priv = db.Column(db.String(),server_default="0")
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    message_id = db.Column(db.String())

class AgentStartup(db.Model):
    __tablename__ = "agentstartup"
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String())
    image = db.Column(db.String())
    command = db.Column(db.String())
    location = db.Column(db.String())
    sid = db.Column(db.String())
    username = db.Column(db.String())
    domain = db.Column(db.String())
    host_name = db.Column(db.String())
    is_priv = db.Column(db.String(),server_default="0")
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    message_id = db.Column(db.String())

class AgentPipe(db.Model):
    __tablename__ = "agentpipe"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String())
    host_name = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    message_id = db.Column(db.String())

class AgentShare(db.Model):
    __tablename__ = "agentshare"
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String())
    allowmaximum = db.Column(db.Boolean)
    accessmask = db.Column(db.String())
    description = db.Column(db.String())
    installdate = db.Column(db.DateTime)
    caption = db.Column(db.String())
    maximumallowed = db.Column(db.String())
    path = db.Column(db.String())
    type = db.Column(db.String())
    wmi_class = db.Column(db.String())
    host_name = db.Column(db.String())
    name = db.Column(db.String())
    type_str = db.Column(db.String())
    permissions = db.Column(db.String())
    passwd = db.Column(db.String())
    current_uses = db.Column(db.BigInteger)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    message_id = db.Column(db.String())

class AgentAdapter(db.Model):
    __tablename__ = "agentadapter"
    id = db.Column(db.Integer, primary_key=True)
    ipxnetworknumber = db.Column(db.String())
    tcpuserfc1122urgentpointer = db.Column(db.String())
    databasepath = db.Column(db.String())
    dnsdomain = db.Column(db.String())
    igmplevel = db.Column(db.String())
    numforwardpackets = db.Column(db.String())
    keepalivetime = db.Column(db.String())
    ipusezerobroadcast = db.Column(db.String())
    defaultipgateway = db.Column(db.String())
    tcpipnetbiosoptions = db.Column(db.Integer)
    dnsdomainsuffixsearchorder = db.Column(db.String())
    deadgwdetectenabled = db.Column(db.String())
    ipxframetype = db.Column(db.String())
    ipenabled = db.Column(db.Boolean)
    ipsubnet = db.Column(db.String())
    dnshostname = db.Column(db.String())
    tcpnumconnections = db.Column(db.String())
    dhcpserver = db.Column(db.String())
    description = db.Column(db.String())
    index = db.Column(db.String())
    arpuseethersnap = db.Column(db.String())
    dnsenabledforwinsresolution = db.Column(db.Boolean)
    ipxmediatype = db.Column(db.String())
    arpalwayssourceroute = db.Column(db.String())
    ipsecpermittcpports = db.Column(db.String())
    defaulttos = db.Column(db.String())
    forwardbuffermemory = db.Column(db.String())
    mtu = db.Column(db.String())
    defaultttl = db.Column(db.String())
    ipxenabled = db.Column(db.String())
    tcpmaxconnectretransmissions = db.Column(db.String())
    dhcpleaseobtained = db.Column(db.String())
    winssecondaryserver = db.Column(db.String())
    winsenablelmhostslookup = db.Column(db.Boolean)
    tcpmaxdataretransmissions = db.Column(db.String())
    domaindnsregistrationenabled = db.Column(db.Boolean)
    ipsecpermitudpports = db.Column(db.String())
    ipxvirtualnetnumber = db.Column(db.String())
    pmtudiscoveryenabled = db.Column(db.String())
    ipfiltersecurityenabled = db.Column(db.Boolean)
    ipconnectionmetric = db.Column(db.Integer)
    ipsecpermitipprotocols = db.Column(db.String())
    pmtubhdetectenabled = db.Column(db.String())
    dhcpleaseexpires = db.Column(db.String())
    fulldnsregistrationenabled = db.Column(db.Boolean)
    ipportsecurityenabled = db.Column(db.String())
    ipaddress = db.Column(db.String())
    dhcpenabled = db.Column(db.Boolean)
    winshostlookupfile = db.Column(db.String())
    dnsserversearchorder = db.Column(db.String())
    macaddress = db.Column(db.String())
    ipxaddress = db.Column(db.String())
    keepaliveinterval = db.Column(db.String())
    wmi_class = db.Column(db.String())
    host_name = db.Column(db.String())
    gatewaycostmetric = db.Column(db.String())
    caption = db.Column(db.String())
    settingid = db.Column(db.String())
    servicename = db.Column(db.String())
    winsprimaryserver = db.Column(db.String())
    interfaceindex = db.Column(db.Integer)
    tcpwindowsize = db.Column(db.String())
    winsscopeid = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    message_id = db.Column(db.String())

class AgentLogon(db.Model):
    __tablename__ = "agentlogon"
    id = db.Column(db.Integer, primary_key=True)
    host_name = db.Column(db.String())
    local_account = db.Column(db.Boolean)
    account_type = db.Column(db.String())
    username = db.Column(db.String())
    logondomain = db.Column(db.String())
    domain = db.Column(db.String())
    authenticationpackage = db.Column(db.String())
    logontype = db.Column(db.String())
    sid = db.Column(db.String())
    logontime = db.Column(db.DateTime)
    logonid = db.Column(db.BigInteger)
    logonserver = db.Column(db.String())
    upn = db.Column(db.String())
    last_password_change = db.Column(db.DateTime)
    password_age = db.Column(db.Integer)
    priv = db.Column(db.Integer)
    comment = db.Column(db.String())
    flags = db.Column(db.Integer)
    useraccountcontrol = db.Column(db.String())
    script_path = db.Column(db.String())
    workstations = db.Column(db.String())
    last_logon = db.Column(db.DateTime)
    last_logoff = db.Column(db.DateTime)
    acct_expires = db.Column(db.DateTime)
    bad_pw_count = db.Column(db.Integer)
    num_logons = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    primary_group_id = db.Column(db.Integer)
    password_expired = db.Column(db.Integer)
    is_priv = db.Column(db.String(),server_default="0")
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    message_id = db.Column(db.String())

class AgentProfile(db.Model):
    __tablename__ = "agentprofile"
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.String())
    workstations = db.Column(db.String())
    codepage = db.Column(db.String())
    logonhours = db.Column(db.String())
    unitsperweek = db.Column(db.String())
    scriptpath = db.Column(db.String())
    homedirectory = db.Column(db.String())
    logonserver = db.Column(db.String())
    countrycode = db.Column(db.String())
    caption = db.Column(db.String())
    privileges = db.Column(db.String())
    name = db.Column(db.String())
    accountexpires = db.Column(db.String())
    wmi_class = db.Column(db.String())
    host_name = db.Column(db.String())
    profile = db.Column(db.String())
    numberoflogons = db.Column(db.BigInteger)
    badpasswordcount = db.Column(db.BigInteger)
    homedirectorydrive = db.Column(db.String())
    description = db.Column(db.String())
    maximumstorage = db.Column(db.String())
    lastlogon = db.Column(db.String())
    authorizationflags = db.Column(db.String())
    passwordexpires = db.Column(db.String())
    lastlogoff = db.Column(db.String())
    primarygroupid = db.Column(db.String())
    passwordage = db.Column(db.String())
    parameters = db.Column(db.String())
    userid = db.Column(db.String())
    usertype = db.Column(db.String())
    settingid = db.Column(db.String())
    flags = db.Column(db.String())
    usercomment = db.Column(db.String())
    fullname = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    message_id = db.Column(db.String())

class AgentSystem(db.Model):
    __tablename__ = "agentsystem"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String())
    domain = db.Column(db.String())
    totalphysicalmemory = db.Column(db.String())
    chassisbootupstate = db.Column(db.Integer)
    hypervisorpresent = db.Column(db.Boolean)
    systemstartupoptions = db.Column(db.String())
    automaticresetbootoption = db.Column(db.Boolean)
    systemskunumber = db.Column(db.String())
    systemfamily = db.Column(db.String())
    automaticresetcapability = db.Column(db.Boolean)
    frontpanelresetstatus = db.Column(db.Integer)
    domainrole = db.Column(db.Integer)
    daylightineffect = db.Column(db.String())
    oemlogobitmap = db.Column(db.String())
    primaryownercontact = db.Column(db.String())
    description = db.Column(db.String())
    numberofprocessors = db.Column(db.Integer)
    adminpasswordstatus = db.Column(db.Integer)
    caption = db.Column(db.String())
    powermanagementsupported = db.Column(db.String())
    pcsystemtypeex = db.Column(db.Integer)
    lastloadinfo = db.Column(db.String())
    wakeuptype = db.Column(db.Integer)
    partofdomain = db.Column(db.Boolean)
    systemstartupsetting = db.Column(db.String())
    nameformat = db.Column(db.String())
    primaryownername = db.Column(db.String())
    currenttimezone = db.Column(db.Integer)
    automaticmanagedpagefile = db.Column(db.Boolean)
    thermalstate = db.Column(db.Integer)
    wmi_class = db.Column(db.String())
    host_name = db.Column(db.String())
    poweronpasswordstatus = db.Column(db.Integer)
    bootstatus = db.Column(db.String())
    workgroup = db.Column(db.String())
    installdate = db.Column(db.String())
    resetcount = db.Column(db.Integer)
    oemstringarray = db.Column(db.String())
    dnshostname = db.Column(db.String())
    pauseafterreset = db.Column(db.Integer)
    initialloadinfo = db.Column(db.String())
    bootromsupported = db.Column(db.Boolean)
    bootupstate = db.Column(db.String())
    creationclassname = db.Column(db.String())
    enabledaylightsavingstime = db.Column(db.Boolean)
    manufacturer = db.Column(db.String())
    keyboardpasswordstatus = db.Column(db.Integer)
    networkservermodeenabled = db.Column(db.Boolean)
    numberoflogicalprocessors = db.Column(db.Integer)
    bootoptiononlimit = db.Column(db.String())
    name = db.Column(db.String())
    roles = db.Column(db.String())
    systemtype = db.Column(db.String())
    resetcapability = db.Column(db.Integer)
    supportcontactdescription = db.Column(db.String())
    chassisskunumber = db.Column(db.String())
    systemstartupdelay = db.Column(db.String())
    powerstate = db.Column(db.Integer)
    status = db.Column(db.String())
    infraredsupported = db.Column(db.Boolean)
    powermanagementcapabilities = db.Column(db.String())
    resetlimit = db.Column(db.Integer)
    model = db.Column(db.String())
    pcsystemtype = db.Column(db.Integer)
    powersupplystate = db.Column(db.Integer)
    bootoptiononwatchdog = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    message_id = db.Column(db.String())

class AgentPatch(db.Model):
    __tablename__ = "agentpatch"
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String())
    installedby = db.Column(db.String())
    description = db.Column(db.String())
    installdate = db.Column(db.String())
    csname = db.Column(db.String())
    servicepackineffect = db.Column(db.String())
    caption = db.Column(db.String())
    installedon = db.Column(db.String())
    fixcomments = db.Column(db.String())
    hotfixid = db.Column(db.String())
    wmi_class = db.Column(db.String())
    host_name = db.Column(db.String())
    name = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    message_id = db.Column(db.String())

class AgentService(db.Model):
    __tablename__ = "agentservice"
    id = db.Column(db.Integer, primary_key=True)
    host_name = db.Column(db.String())
    image = db.Column(db.String())
    arguments = db.Column(db.String())
    registry_name = db.Column(db.String())
    service_type = db.Column(db.String())
    start_type = db.Column(db.String())
    dependencies = db.Column(db.JSON)
    display_name = db.Column(db.String())
    description = db.Column(db.String())
    command = db.Column(db.String())
    status = db.Column(db.String())
    hash = db.Column(db.String())
    username = db.Column(db.String())
    sid = db.Column(db.String())
    domain = db.Column(db.String())
    account_type = db.Column(db.String())
    is_priv = db.Column(db.String(),server_default="0")
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    message_id = db.Column(db.String())

class AgentProcess(db.Model):
    __tablename__ = "agentprocess"
    id = db.Column(db.Integer, primary_key=True)
    host_name = db.Column(db.String())
    image = db.Column(db.String())
    username = db.Column(db.String())
    pid = db.Column(db.Integer)
    ppid = db.Column(db.Integer)
    sid = db.Column(db.String())
    domain = db.Column(db.String())
    account_type = db.Column(db.String)
    status = db.Column(db.String())
    num_handles = db.Column(db.Integer)
    num_threads = db.Column(db.Integer)
    hash = db.Column(db.String())
    cwd = db.Column(db.String())
    exe = db.Column(db.String())
    cmdline = db.Column(db.String())
    cpu_percent  = db.Column(db.Float)
    memory_percent  = db.Column(db.Float)
    is_running = db.Column(db.Boolean())
    create_time = db.Column(db.DateTime)
    parent_count = db.Column(db.Integer)
    children_count = db.Column(db.Integer)
    is_priv = db.Column(db.String(),server_default="0")
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())

    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    message_id = db.Column(db.String())
    # network connections ref
    # parents ref
    # children ref

class AgentNetSession(db.Model):
    __tablename__ = "agentnetsession"
    id = db.Column(db.Integer, primary_key=True)
    client_name = db.Column(db.String())
    user_name = db.Column(db.String())
    client_host = db.Column(db.String())
    num_opens = db.Column(db.BigInteger)
    active_time = db.Column(db.BigInteger)
    idle_time = db.Column(db.BigInteger)
    user_flags = db.Column(db.BigInteger)
    client_type = db.Column(db.String())
    transport = db.Column(db.String())
    host_name = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    message_id = db.Column(db.String())

'''
class AgentNetUse(db.Model):
    __tablename__ = "agentnetuse"
    id = db.Column(db.Integer, primary_key=True)
    status_str = db.Column(db.String())
    local = db.Column(db.String())
    remote = db.Column(db.String())
    status = db.Column(db.Integer)
    host_name = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
'''

class AgentNet(db.Model):
    __tablename__ = "agentnet"
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String())
    raddr = db.Column(db.String())
    family = db.Column(db.String())
    host_name = db.Column(db.String())
    pid = db.Column(db.String())
    lport = db.Column(db.BigInteger)
    pname = db.Column(db.String())
    laddr = db.Column(db.String())
    rport = db.Column(db.BigInteger)
    private = db.Column(db.Boolean())
    username = db.Column(db.String())
    account_type = db.Column(db.String())
    sid = db.Column(db.String())
    domain = db.Column(db.String())
    exe = db.Column(db.String())
    image = db.Column(db.String())
    cmdline = db.Column(db.String())
    country_code = db.Column(db.String())
    country_name = db.Column(db.String())
    region_name = db.Column(db.String())
    city_name = db.Column(db.String())
    lat = db.Column(db.Float)
    long = db.Column(db.Float)
    is_priv = db.Column(db.String(),server_default="0")
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    message_id = db.Column(db.String())

class AgentUpdates(db.Model):
    __tablename__ = "agentupdates"
    id = db.Column(db.Integer, primary_key=True)
    host_name = db.Column(db.String())
    main_category = db.Column(db.String())
    update_type = db.Column(db.String())
    installed = db.Column(db.Boolean())
    downloaded = db.Column(db.Boolean())
    severity = db.Column(db.String())
    needsreboot = db.Column(db.Boolean())
    mandatory = db.Column(db.Boolean())
    title = db.Column(db.String())
    hidden = db.Column(db.Boolean())
    description = db.Column(db.String())
    guid = db.Column(db.String())
    kbs = db.Column(db.String())
    categories = db.Column(db.String())
    last_published = db.Column(db.DateTime)
#haaaaa
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    message_id = db.Column(db.String())

#class AgentSoftware(db.Model,AgentMixin):
class AgentSoftware(db.Model):
    __tablename__ = "agentsoftware"
    id = db.Column(db.Integer, primary_key=True)
    publisher = db.Column(db.String())
    displayname = db.Column(db.String())
    installdate = db.Column(db.String())
    uninstallstring = db.Column(db.String())
    majorversion = db.Column(db.Integer)
    host_name = db.Column(db.String())
    installsource = db.Column(db.String())
    estimatedsize = db.Column(db.Integer)
    version = db.Column(db.String())
    displayversion = db.Column(db.String())
    modifypath = db.Column(db.String())
    minorversion = db.Column(db.Integer)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    message_id = db.Column(db.String())
    #agentname = db.relationship("Agent") # use this for the AgentMixin class and call <query.first().inc_host()>

class AgentInteract(db.Model):
    __tablename__ = 'agentinteract'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String())
    campaign = db.Column(db.Boolean(),default=False)
    session = db.Column(db.String())
    cmd = db.Column(db.String())
    complete = db.Column(db.Integer, server_default='0')
    cwd = db.Column(db.String())
    host_name = db.Column(db.String())
    data = db.Column(db.JSON)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)

class AgentJob(db.Model):
    __tablename__ = "agentjob"
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer)
    jobset = db.Column(db.JSON)
    uninstall = db.Column(db.Integer, server_default='0')
    update = db.Column(db.Integer, server_default='0')
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)

class AgentUser(db.Model):
    __tablename__ = "agentuser"
    id = db.Column(db.Integer, primary_key=True)
    host_name = db.Column(db.String())
    local_account = db.Column(db.Boolean)
    username = db.Column(db.String())
    domain = db.Column(db.String())
    sid = db.Column(db.String())
    last_password_change = db.Column(db.DateTime)
    password_age = db.Column(db.Integer)
    priv = db.Column(db.Integer)
    comment = db.Column(db.String())
    flags = db.Column(db.Integer)
    useraccountcontrol = db.Column(db.String())
    script_path = db.Column(db.String())
    last_logon = db.Column(db.DateTime)
    last_logoff = db.Column(db.DateTime)
    acct_expires = db.Column(db.DateTime)
    bad_pw_count = db.Column(db.Integer)
    num_logons = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    primary_group_id = db.Column(db.Integer)
    password_expired = db.Column(db.Integer)
    groups = db.Column(db.JSON())
    account_type = db.Column(db.String())

    managed = db.Column(db.Boolean,server_default='0') # managed user_accounts
    password_length = db.Column(db.Integer,server_default='20')
    password_rotation = db.Column(db.Integer,server_default='60')
    last_password_sync = db.Column(db.DateTime)
    in_sync = db.Column(db.Boolean,server_default='0')
    # settings below to possibly place in separate table for easier management
    rotate_after_checkout = db.Column(db.Boolean,server_default='0')
    rotate_now = db.Column(db.Boolean,server_default='0')
    rotate_method = db.Column(db.String(),server_default="change")
    reconcile = db.Column(db.Boolean,server_default='1')
    disable = db.Column(db.Boolean,server_default='0')
    is_priv = db.Column(db.String(),server_default="0")
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    password_sync = db.relationship("LocalUserManaged",backref="agentuser", lazy="dynamic")
#haaaaaa
#    managed_logs = db.relationship("ManagedLocalLogs",backref="agentuser", lazy="dynamic")
    #vault_id = db.Column(db.Integer, db.ForeignKey('vault.id'))
    message_id = db.Column(db.String())

'''
class ManagedLocalLogs(db.Model):
    __tablename__ = "managedlocallogs"
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String())
    message = db.Column(db.String())
    result = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// User ref
    user_id = db.Column(db.Integer, db.ForeignKey('agentuser.id'), nullable=False)

class ManagedDomainLogs(db.Model):
    __tablename__ = "manageddomainlogs"
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String())
    message = db.Column(db.String())
    result = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// User ref
    user_id = db.Column(db.Integer, db.ForeignKey('ad_user.id'), nullable=False)
'''

class LocalUserManaged(db.Model):
    __tablename__ = "localuser_managed"
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String())
    success = db.Column(db.Boolean)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// User ref
    user_id = db.Column(db.Integer, db.ForeignKey('agentuser.id'), nullable=False)

class AgentGroup(db.Model):
    __tablename__ = "agentgroup"
    id = db.Column(db.Integer, primary_key=True)
    # If collecting local groups via API
    members = db.Column(db.JSON())
    members_count = db.Column(db.Integer)
    domain_accounts = db.Column(db.Integer)
    local_account = db.Column(db.Boolean)
    group = db.Column(db.String())
    account_type = db.Column(db.String())
    description = db.Column(db.String())
    host_name = db.Column(db.String())
    '''
    # If collecting local groups with wmi
    status = db.Column(db.String())
    domain = db.Column(db.String())
    name = db.Column(db.String())
    installdate = db.Column(db.String())
    localaccount = db.Column(db.Boolean)
    caption = db.Column(db.String())
    sid = db.Column(db.String())
    sidtype = db.Column(db.Integer)
    wmi_class = db.Column(db.String())
    host_name = db.Column(db.String())
    description = db.Column(db.String())
    '''

    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    message_id = db.Column(db.String())

# ACTIVE DIRECTORY
class ADDomain(db.Model):
    __tablename__ = "ad_domain"
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String())
    uascompat = db.Column(db.Integer)
    msdsperusertrusttombstonesquota = db.Column(db.Integer)
    minpwdlength = db.Column(db.Integer)
    minpwdage = db.Column(db.DateTime)
    usnchanged = db.Column(db.DateTime)
    instancetype = db.Column(db.Integer)
    whencreated = db.Column(db.DateTime)
    dc = db.Column(db.String()) 
    usncreated = db.Column(db.DateTime)
    msdsmachineaccountquota = db.Column(db.Integer)
    fsmoroleowner = db.Column(db.String()) 
    modifiedcountatlastprom = db.Column(db.DateTime)
    objectclass = db.Column(db.String()) 
    msdsalluserstrustquota = db.Column(db.Integer)
    dscorepropagationdata = db.Column(db.DateTime)
    msdsbehaviorversion = db.Column(db.Integer)
    distinguishedname = db.Column(db.String()) 
    msdsperusertrustquota = db.Column(db.Integer)
    whenchanged = db.Column(db.DateTime)
    msdsisdomainfor = db.Column(db.String()) 
    ridmanagerreference = db.Column(db.String()) 
    modifiedcount = db.Column(db.DateTime)
    nextrid = db.Column(db.Integer)
    serverstate = db.Column(db.Integer)
    name = db.Column(db.String()) 
    creationtime = db.Column(db.DateTime)
    systemflags = db.Column(db.String()) 
    iscriticalsystemobject = db.Column(db.Boolean)
    gplink = db.Column(db.String()) 
    msdsexpirepasswordsonsmartcardonlyaccounts = db.Column(db.Boolean)
    objectcategory = db.Column(db.String())     

    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    host_name = db.Column(db.String())
    message_id = db.Column(db.String())

class ADComputer(db.Model):
    __tablename__ = "ad_computer"
    id = db.Column(db.Integer, primary_key=True)
    
    domain = db.Column(db.String())
    useraccountcontrol = db.Column(db.String())
    operatingsystem  = db.Column(db.String())
    cn  = db.Column(db.String())
    name  = db.Column(db.String())
    whencreated = db.Column(db.DateTime)
    objectclass = db.Column(db.String())
    distinguishedname = db.Column(db.String())
    pwdlastset = db.Column(db.DateTime)
    operatingsystemservicepack = db.Column(db.String())
    serviceprincipalname = db.Column(db.String())
    msdssupportedencryptiontypes = db.Column(db.String())
    usncreated = db.Column(db.DateTime)
    lastlogoff = db.Column(db.DateTime)
    badpasswordtime  = db.Column(db.DateTime)
    lastlogon = db.Column(db.DateTime)
    objectcategory = db.Column(db.String())
    lastlogontimestamp = db.Column(db.DateTime)
    whenchanged = db.Column(db.DateTime)
    primarygroupid = db.Column(db.String())
    instancetype = db.Column(db.String())
    logoncount = db.Column(db.Integer)
    samaccountname = db.Column(db.String())
    operatingsystemversion = db.Column(db.String())
    dnshostname = db.Column(db.String())
    samaccounttype = db.Column(db.String())
    usnchanged = db.Column(db.DateTime)
    memberof_count = db.Column(db.Integer)
    memberof = db.Column(db.JSON())
    
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    domain_id = db.Column(db.Integer, db.ForeignKey('ad_domain.id'), nullable=True)
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    host_name = db.Column(db.String())
    message_id = db.Column(db.String())

class ADUser(db.Model):
    __tablename__ = "ad_user"
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String())
    useraccountcontrol = db.Column(db.String())
    primarygroupid = db.Column(db.String())  
    lastlogoff = db.Column(db.DateTime)
    serviceprincipalname = db.Column(db.String())
    badpasswordtime = db.Column(db.DateTime)
    cn = db.Column(db.String())
    name = db.Column(db.String())
    lastlogon = db.Column(db.DateTime)
    lastlogontimestamp = db.Column(db.DateTime)
    lastlogoff = db.Column(db.DateTime)
    pwdlastset = db.Column(db.DateTime)
    title = db.Column(db.String())
    distinguishedname = db.Column(db.String())
    department = db.Column(db.String())
    objectsid = db.Column(db.String())
    whencreated = db.Column(db.DateTime)
    whenchanged = db.Column(db.DateTime)
    description = db.Column(db.String())
    samaccountname = db.Column(db.String())
    userprincipalname = db.Column(db.String())
    displayname = db.Column(db.String())
    objectclass = db.Column(db.String())
    logoncount = db.Column(db.Integer)
    admincount = db.Column(db.Integer)
    samaccounttype = db.Column(db.String())
    memberof_count = db.Column(db.Integer)
    memberof = db.Column(db.JSON())

    managed = db.Column(db.Boolean,server_default='0') # managed user_accounts
    password_length = db.Column(db.Integer,server_default='20')
    password_rotation = db.Column(db.Integer,server_default='60')
    last_password_sync = db.Column(db.DateTime)
    in_sync = db.Column(db.Boolean,server_default='0')
    # settings below to possibly place in separate table for easier management
    rotate_after_checkout = db.Column(db.Boolean,server_default='0')
    rotate_now = db.Column(db.Boolean,server_default='0')
    rotate_method = db.Column(db.String(),server_default="change")
    reconcile = db.Column(db.Boolean,server_default='1')

    disable = db.Column(db.Boolean,server_default='0')
    password_expires = db.Column(db.Boolean,server_default='0')
    logon_workstations = db.Column(db.String(),server_default="")
    is_priv = db.Column(db.String(),server_default="0")
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    domain_id = db.Column(db.Integer, db.ForeignKey('ad_domain.id'), nullable=True)
    password_sync = db.relationship("DomainUserManaged",backref="ad_user", lazy="dynamic")
#    managed_logs = db.relationship("ManagedDomainLogs",backref="ad_user", lazy="dynamic")
    #vault_id = db.Column(db.Integer, db.ForeignKey('vault.id'))
#haaaaa
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    host_name = db.Column(db.String())
    message_id = db.Column(db.String())

class DomainUserManaged(db.Model):
    __tablename__ = "domainuser_managed"
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String())
    success = db.Column(db.Boolean)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// User ref
    user_id = db.Column(db.Integer, db.ForeignKey('ad_user.id'), nullable=False)

class ADGroup(db.Model):
    __tablename__ = "ad_group"
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String())
    distinguishedname = db.Column(db.String())
    iscriticalsystemobject = db.Column(db.Boolean)
    systemflags = db.Column(db.String())
    samaccountname = db.Column(db.String())
    cn = db.Column(db.String())
    name = db.Column(db.String())
    whenchanged = db.Column(db.DateTime)
    admincount = db.Column(db.Integer)
    grouptype = db.Column(db.String())
    usnchanged = db.Column(db.DateTime)
    objectcategory = db.Column(db.String())
    usncreated = db.Column(db.DateTime)
    instancetype = db.Column(db.Integer)
    samaccounttype = db.Column(db.String())
    description = db.Column(db.String())
    whencreated = db.Column(db.DateTime)
    objectclass = db.Column(db.String())
    mail = db.Column(db.String())
    objectsid = db.Column(db.String())
    memberof_count = db.Column(db.Integer)
    members_count = db.Column(db.Integer)
    memberof = db.Column(db.JSON())
    members = db.Column(db.JSON())

    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    domain_id = db.Column(db.Integer, db.ForeignKey('ad_domain.id'), nullable=True)
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    host_name = db.Column(db.String())
    message_id = db.Column(db.String())

class ADSysvol(db.Model):
    __tablename__ = "ad_sysvol"
    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.String())
    user_ace = db.Column(db.Integer)
    computer_ace = db.Column(db.Integer)
    group_ace = db.Column(db.Integer)
    name = db.Column(db.String())
    hash = db.Column(db.String())
    acecount = db.Column(db.Integer)
    aces = db.Column(db.JSON())
    access = db.Column(db.DateTime)
    modify = db.Column(db.DateTime)
    create = db.Column(db.DateTime)
    size = db.Column(db.BigInteger)
    hash = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    domain_id = db.Column(db.Integer, db.ForeignKey('ad_domain.id'), nullable=True)
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    host_name = db.Column(db.String())
    message_id = db.Column(db.String())

class ADGpo(db.Model):
    __tablename__ = "ad_gpo"
    id = db.Column(db.Integer, primary_key=True)

    domain = db.Column(db.String())
    usnchanged = db.Column(db.DateTime)
    showinadvancedviewonly = db.Column(db.Boolean)
    whenchanged = db.Column(db.DateTime)
    cn = db.Column(db.String())
    iscriticalsystemobject = db.Column(db.Boolean)
    systemflags = db.Column(db.String())
    gpcfilesyspath = db.Column(db.String())
    distinguishedname = db.Column(db.String())
    displayname = db.Column(db.String())
    versionnumber = db.Column(db.String())
    gpcfunctionalityversion = db.Column(db.Integer)
    whencreated = db.Column(db.DateTime)
    objectcategory = db.Column(db.String())
    instancetype = db.Column(db.Integer)
    objectclass = db.Column(db.String())
    gpcmachineextensionnames = db.Column(db.String())
    gpcuserextensionnames = db.Column(db.String())
    usncreated = db.Column(db.DateTime)
    name = db.Column(db.String())

    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    domain_id = db.Column(db.Integer, db.ForeignKey('ad_domain.id'), nullable=True)
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    host_name = db.Column(db.String())
    message_id = db.Column(db.String())

class ADOu(db.Model):
    __tablename__ = "ad_ou"
    id = db.Column(db.Integer, primary_key=True)

    domain = db.Column(db.String())
    usnchanged = db.Column(db.DateTime)
    whenchanged = db.Column(db.DateTime)
    iscriticalsystemobject = db.Column(db.Boolean)
    systemflags = db.Column(db.String())
    usncreated = db.Column(db.DateTime)
    distinguishedname = db.Column(db.String())
    description = db.Column(db.String())
    ou = db.Column(db.String())
    gplink = db.Column(db.String())
    whencreated = db.Column(db.DateTime)
    objectcategory = db.Column(db.String())
    instancetype = db.Column(db.Integer)
    objectclass = db.Column(db.String())
    name = db.Column(db.String())

    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    domain_id = db.Column(db.Integer, db.ForeignKey('ad_domain.id'), nullable=True)
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    host_name = db.Column(db.String())
    message_id = db.Column(db.String())

class ADDc(db.Model):
    __tablename__ = "ad_dc"
    id = db.Column(db.Integer, primary_key=True)

    domain = db.Column(db.String())
    usnchanged = db.Column(db.DateTime)
    showinadvancedviewonly = db.Column(db.Boolean)
    whenchanged = db.Column(db.DateTime)
    cn = db.Column(db.String())
    systemflags = db.Column(db.String())
    usncreated = db.Column(db.DateTime)
    distinguishedname = db.Column(db.String())
    whencreated = db.Column(db.DateTime)
    objectcategory = db.Column(db.String())
    instancetype = db.Column(db.Integer)
    objectclass = db.Column(db.String())
    dnshostname = db.Column(db.String())
    name = db.Column(db.String())
    serverreference = db.Column(db.String())

    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    #// Ref
    domain_id = db.Column(db.Integer, db.ForeignKey('ad_domain.id'), nullable=True)
    host_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    host_name = db.Column(db.String())
    message_id = db.Column(db.String())

