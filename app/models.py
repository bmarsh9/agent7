from flask import current_app
from sqlalchemy.sql import func,text
from rq_scheduler import Scheduler
from redis import Redis
from rq import Queue
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

'''
class SnapPass(db.Model):
    __tablename__ = 'snappass'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.JSON())
    until = db.Column(db.BigInteger)
    burned = db.Column(db.Boolean,server_default='0')
    access_ip = db.Column(db.String())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())

class SMConnection(db.Model):
    __tablename__ = 'sm_connection'
    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String())
    quick_link = db.Column(db.String())
    connection_details = db.Column(db.JSON())
    remove_after = db.Column(db.DateTime)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    guac_id = db.Column(db.Integer, db.ForeignKey('guacsm.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

#TESTING VAULT ROLES
# Define the Role data model
class Vault(db.Model):
    __tablename__ = 'vault'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), nullable=False, server_default=u'', unique=True)
    label = db.Column(db.Unicode(255), server_default=u'')
    localaccounts = db.relationship("AgentUser",backref="vault", lazy="dynamic")
    domainaccounts = db.relationship("ADUser",backref="vault", lazy="dynamic")

class VaultRoles(db.Model):
    __tablename__ = 'vault_roles'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
    vault_id = db.Column(db.Integer(), db.ForeignKey('vault.id', ondelete='CASCADE'))

class GuacSM(db.Model):
    __tablename__ = 'guacsm'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String())
    host = db.Column(db.String()) # can be ip or hostname
    status = db.Column(db.Boolean,server_default='0')
    token = db.Column(db.String())
    last_ping = db.Column(db.DateTime)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())

class ScanAssessment(db.Model):
    __tablename__ = 'scan_assessment'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String())
    targets = db.Column(db.String())
    arguments = db.Column(db.String())
    schedule = db.Column(db.String())
    scheduled_start = db.Column(db.String())
    scan_start = db.Column(db.DateTime)
    scan_end = db.Column(db.DateTime)
    elapsed = db.Column(db.Float)
    uphosts = db.Column(db.Integer)
    downhosts = db.Column(db.Integer)
    totalhosts = db.Column(db.Integer)
    percentage_up = db.Column(db.Integer)
    uniq_family = db.Column(db.String())
    uniq_os = db.Column(db.String())
    total_ports_open = db.Column(db.Integer())
    uniq_ports_open = db.Column(db.Integer())
    total_services = db.Column(db.Integer())
    uniq_services = db.Column(db.Integer())
    meta_services = db.Column(db.JSON())
    meta_ports = db.Column(db.JSON())
    meta_os = db.Column(db.JSON())
    meta_family = db.Column(db.JSON())
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    # Ref
    hosts = db.relationship("ScanData",backref="assessment", lazy="dynamic")

class ScanData(db.Model):
    __tablename__ = 'scan_data'
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String())
    hostname = db.Column(db.String())
    state = db.Column(db.String())
    uptime = db.Column(db.String())
    last_boot = db.Column(db.String())
    os = db.Column(db.String())
    accuracy = db.Column(db.String())
    type = db.Column(db.String())
    vendor = db.Column(db.String())
    osfamily = db.Column(db.String())
    osgen = db.Column(db.String())
    os_data = db.Column(db.JSON())
    port_data = db.Column(db.JSON())
    ports_open = db.Column(db.Integer())
    critical_severity = db.Column(db.Integer())
    high_severity = db.Column(db.Integer())
    medium_severity = db.Column(db.Integer())
    services = db.Column(db.Integer())
    country_code = db.Column(db.String())
    country_name = db.Column(db.String())
    region_name = db.Column(db.String())
    city_name = db.Column(db.String())
    lat = db.Column(db.Float)
    long = db.Column(db.Float)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())
    # Ref
    assessment_id = db.Column(db.Integer, db.ForeignKey('scan_assessment.id'), nullable=False)

'''

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
#    software = db.relationship("AgentSoftware",backref="agent", lazy="joined")
#    software = db.relationship("AgentSoftware",backref=db.backref("agent", lazy="immediate"))

#    def __repr__(self):
#        return "<Agent: {}>".format(self.hostname)

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
    # reset_password_token = db.Column(db.String(100), nullable=False, server_default='')
    active = db.Column(db.Boolean(), nullable=False, server_default='0')
    otp_secret = db.Column(db.String(), default=base64.b32encode(os.urandom(10)).decode('utf-8'))
    mfa_enabled = db.Column(db.Boolean(),  server_default='0')
    provisioning_qr = db.Column(db.Boolean(),  server_default='0')

    # User information
    active = db.Column('is_active', db.Boolean(), nullable=False, server_default='0')
    first_name = db.Column(db.Unicode(50), nullable=False, server_default=u'')
    last_name = db.Column(db.Unicode(50), nullable=False, server_default=u'')

    # Relationships
    roles = db.relationship('Role', secondary='users_roles',
                            backref=db.backref('users', lazy='dynamic'))

#    vaults = db.relationship('Vault', secondary='vault_roles',
#                            backref=db.backref('users', lazy='dynamic'))

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
    # save the user of the invitee
    invited_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    invited_by_user = db.relationship('User', uselist=False)
    # token used for registration page to identify user registering
    token = db.Column(db.String(100), nullable=False, server_default='')

# # Define the User registration form
# # It augments the Flask-User RegisterForm with additional fields
# class MyRegisterForm(RegisterForm):
#     first_name = StringField('First name', validators=[
#         validators.DataRequired('First name is required')])
#     last_name = StringField('Last name', validators=[
#         validators.DataRequired('Last name is required')])


# Define the User profile form
class UserProfileForm(FlaskForm):
    first_name = StringField('First name', validators=[
        validators.DataRequired('First name is required')])
    last_name = StringField('Last name', validators=[
        validators.DataRequired('Last name is required')])
    submit = SubmitField('Save')

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

#----------------------------------- Task Database
class Tasks(db.Model):
    '''
    Database table for background tasks. All other tables should have a field
        with `task_id = db.Column(db.String, db.ForeignKey('tasks.id')) #// Set a foreign key`
    '''
    __tablename__ = 'tasks'
    id = db.Column(db.String(100),primary_key=True)
    repeat_id = db.Column(db.Integer()) #// Repeat id is if the task repeats we need a id other than the job_id
    name = db.Column(db.String(128))
    queue = db.Column(db.String(128))
    active = db.Column(db.Boolean, server_default='1')
    interval = db.Column(db.Integer)
    repeat = db.Column(db.Integer,server_default='0')
    repeating_bool = db.Column(db.Boolean, server_default='0')
    func_args = db.Column(db.JSON)
    category = db.Column(db.String) #// The category of the task (bloodhound,dns,etc.)
    description = db.Column(db.String(128))
    complete = db.Column(db.Boolean, server_default='0')
    progress = db.Column(db.Integer, server_default='0')
    error = db.Column(db.Integer)
    forever = db.Column(db.Boolean, server_default='0')
    start_time = db.Column(db.DateTime)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())

    def get_rq_func(self,name):
        '''
        .Description --> Return the function for the rq job names
        '''
        job_names = {
            "test": "app.agent.tasks.test_alert",
            "scan": "app.agent.tasks.scan",
            "enrich_network_connections": "app.agent.tasks.enrich_network_connections",
            "start_onboarding_workflow": "app.agent.tasks.start_onboarding_workflow",
            "update_priv_users": "app.agent.tasks.update_privilged_user_tables",
            "update_bi_group_ledger": "app.agent.tasks.update_built_in_group_ledger_table",
            "insight": "app.insights.dev.rq_insights",
            "guac_ping": "app.agent.tasks.guac_ping",
        }
        j = job_names.get(name,None)
        if not j:
            current_app.logger.error("Requested RQscheduler task does not exist: {}".format(name))
        return j

    def launch_task(self,queue,name,repeat=0,interval=60,start_time=None,func_args={},**kwargs):
        #//Add 5 second lag to the start_time so the job ID can be added to the database before the task completes
        if not start_time:
            start_time = (datetime.datetime.utcnow() + datetime.timedelta(seconds=5))

        #"2019-02-14 16" start_time format
        if start_time and isinstance(start_time,str): #convert to datetime object
            start_time = datetime.datetime.strptime(start_time,"%Y-%m-%d %H")

        #// Push task to scheduler
        scheduler = current_app.queues[queue]
        rq_job = scheduler.schedule(
            scheduled_time=start_time,           # Time for first execution, in UTC timezone datetime.datetime(2020, 1, 1, 3, 4)
            func=self.get_rq_func(name),                           # Function to be queued
            kwargs=func_args, # Keyword arguments passed into function when executed
            interval=interval,                   # Time before the function is called again, in seconds
            repeat=repeat,                        # Repeat this number of times (None means repeat forever)
            timeout=18000 # 5 hours
        )

        current_app.logger.info("Added task to RQscheduler. Queue:{}, Job_ID:{}".format(queue,rq_job.get_id()))

        #// Build Job record for database
        task = Tasks(id=str(rq_job.get_id()),name=name,queue=queue,repeat=repeat,
            interval=interval,func_args=func_args,start_time=start_time)

        #// Repeating task
        if repeat is not None and repeat is not 0 and repeat is not 1:
            setattr(task,"repeat_id",0)
            setattr(task,"repeating_bool",True)

        #// Forever task
        if repeat is None:
          task.forever = True

        #// Commit to db
        db.session.add(task)
        db.session.commit()

        return True

    @staticmethod
    def update_task(id,progress):
        id = str(id)
        record = Tasks.query.filter_by(id=id).order_by(Tasks.repeat_id.desc()).first()
        if record:
            #// If task repeats, grab the last repeat_id and add a count to it
            if record.repeating_bool:

                record.repeat_id += 1

                #// If task repeats and the current update is 100 (successful) / else failed
                if progress is 100:
                    progress = int(100 * float(record.repeat_id)/float(record.repeat))
                    record.progress = progress
            else:
                record.progress = progress

            if progress is 100:
                record.complete = True
            db.session.commit()

            return True
        return False

    @staticmethod
    def stop_task(id):
        id = str(id)
        #// Get queue name and cancel it
        record = Tasks.query.filter_by(id=id).first()
        if record:
            scheduler = current_app.queues[record.queue]
            scheduler.cancel(id)

            #// Update the record in the database
            record.active = False
            db.session.commit()

            return True
        return False

    @staticmethod
    def get_task(key_list=list(), **kwargs):
        """
        DEPRECATED
        .Ex: print Tasks.get_task(key_list=["id","progress"],id="a7410198-d0d6-41a8-9f9d-cf609d910162",progress=100)
        """
        dataset = []
        try:
            #// Query all tasks with filters
            data = db.session.query(Tasks)
            for k,v in kwargs.items():
                data = data.filter(getattr(Tasks,k)==v)
            results = data.all()

            for record in results:
                if record.repeat == record.repeat_id and record.progress is not 100:
                    task_failed = True
                else:
                    task_failed = False
                if key_list:
                    temp_dic = {}
                    for k,v in record.__dict__.items():
                        if k in key_list:
                            temp_dic[k] = v
                    temp_dic["task_failed"] = task_failed
                    dic.append(temp_dic)
                else:
                    record.__dict__.pop("_sa_instance_state")
                    record.__dict__["task_failed"] = task_failed
                    dataset.append(record.__dict__)
        except Exception as e:
            return e
        return dataset

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

