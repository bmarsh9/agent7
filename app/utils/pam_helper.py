from app.models import *
from app import db
import ast
from sqlalchemy import func
from datetime import datetime
import arrow
from app.utils.ad_helper import ADHelper
from app.utils.agent_helper import AgentHelper

class PamHelper():
    def __init__(self):
        pass

    def get_priv_users_local(self):
        local = AgentHelper().get_privileged_users()
        return local

    def get_priv_users_domain(self):
        domain = ADHelper().get_priv_users()
        return domain

    def get_priv_users(self):
        local = AgentHelper().get_privileged_users()
        domain = ADHelper().get_priv_users()
        all_priv_users = local + domain
        return all_priv_users

    def get_data_for_priv_users(self):
        users = self.get_priv_users()
        for user in users:
            if hasattr(user,"sid"):
                sid = user.sid
            else:
                sid = user.objectsid
            processes = self.get_process_for_user(sid)
            schtasks = self.get_schtask_for_user(sid)
            services = self.get_service_for_user(sid)
            startup = self.get_startup_for_user(sid)
            logon = self.get_logon_for_user(sid)
            print(processes,schtasks,services,startup,logon)

    # query for single user
    def get_process_for_user(self,sid):
        return AgentProcess.query.filter(AgentProcess.sid == sid).order_by(AgentProcess.id.desc()).all()

    def get_schtask_for_user(self,sid):
        return AgentSchTask.query.filter(AgentSchTask.sid == sid).order_by(AgentSchTask.id.desc()).all()

    def get_service_for_user(self,sid):
        return AgentService.query.filter(AgentService.sid == sid).order_by(AgentService.id.desc()).all()

    def get_startup_for_user(self,sid):
        return AgentStartup.query.filter(AgentStartup.sid == sid).order_by(AgentStartup.id.desc()).all()

    def get_logon_for_user(self,sid):
        return AgentLogon.query.filter(AgentLogon.sid == sid).order_by(AgentLogon.id.desc()).all()

    def get_connection_for_user(self,sid):
        return AgentNet.query.filter(AgentNet.sid == sid).order_by(AgentNet.id.desc()).all()

    # query for all user
    def get_process_for_priv_users(self):
        data = []
        users = self.get_priv_users()
        for user in users:
            if hasattr(user,"sid"):
                sid = user.sid
            else:
                sid = user.objectsid
            data += self.get_process_for_user(sid)
        return data

    def get_schtask_for_priv_users(self):
        data = []
        users = self.get_priv_users()
        for user in users:
            if hasattr(user,"sid"):
                sid = user.sid
            else:
                sid = user.objectsid
            data += self.get_schtask_for_user(sid)
        return data

    def get_service_for_priv_users(self):
        data = []
        users = self.get_priv_users()
        for user in users:
            if hasattr(user,"sid"):
                sid = user.sid
            else:
                sid = user.objectsid
            data += self.get_service_for_user(sid)
        return data

    def get_startup_for_priv_users(self):
        data = []
        users = self.get_priv_users()
        for user in users:
            if hasattr(user,"sid"):
                sid = user.sid
            else:
                sid = user.objectsid
            data += self.get_startup_for_user(sid)
        return data

    def get_logon_for_priv_users(self):
        data = []
        users = self.get_priv_users()
        for user in users:
            if hasattr(user,"sid"):
                sid = user.sid
            else:
                sid = user.objectsid
            data += self.get_logon_for_user(sid)
        return data

    def get_connections_for_priv_users(self):
        data = []
        users = self.get_priv_users()
        for user in users:
            if hasattr(user,"sid"):
                sid = user.sid
            else:
                sid = user.objectsid
            data += self.get_connection_for_user(sid)
        return data
