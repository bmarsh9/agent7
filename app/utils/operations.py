from app.models import Group, Agent, Job, AgentsGroups, AgentCmd, User, ADGroup, ADUser, ADComputer
#from app.utils.db_helper import DynamicQuery # may use this advanced querying
from sqlalchemy import func,or_
from app import db
import json
'''
class CrudMixin(object):
    def update(self, commit=True, **kwargs):
        for attr, value in kwargs.iteritems():
            setattr(self, attr, value)
        return commit and self.save() or self

    @classmethod
    def create(cls, **kwargs):
        instance = cls(**kwargs)
        return instance.save()

    def save(self, commit=True):
        db.session.add(self)
        if commit:
            db.session.commit()
        return self

    def delete(self, commit=True):
        db.session.delete(self)
        return commit and db.session.commit()
'''


class UserOps():
    def __init__(self, id):
        self.id = id

    def get_roles(self):
        q=User.query.get(self.id)
        if q:
            return q.roles
        return []

class AgentOps():
    def __init__(self, aid):
        self.aid = aid

    def get_hostname(self):
        a = Agent.query.filter(Agent.id == self.aid).first()
        if a:
            return a.hostname
        return None

    def get_version(self):
        version = "0"
        for group in self.get_groups():
            g_version = group.agentversion
            if g_version > version:
                version = g_version
        return version

    def get_job_ex(self):
        a = Agent.query.get(self.aid)
        if a:
            g = a.groups
            if g:
                return g[0].job.data["jobset"]
        return {}

    def get_groups(self):
        q=Agent.query.get(self.aid)
        if q:
            return q.groups
        return []

    def has_group(self, name):
        for group in self.get_groups():
            if name == group.name:
                return True
        return False

    def get_raw_jobs(self):
        jobs_from_groups = []
        for group in self.get_groups():
            if group.job:
                jobs_from_groups.append(group.job)
        return jobs_from_groups

    def has_job(self, name):
        for job in self.get_raw_jobs():
            if name == job.name:
                return True
        return False

    def get_job(self):
        tasklist = dict()
        for job in self.get_raw_jobs():
            for task in job.data["jobset"]:
                task["priority"] = job.priority
                key = (task['task'])
                if key not in tasklist or tasklist[key]['priority'] < task['priority']:
                    tasklist[key] = task
        job = list(tasklist.values())
        return job

    def get_raw_auditkey(self):
        akey_from_groups = []
        for group in self.get_groups():
            akey_from_groups.append(group.akey)
        return akey_from_groups

    def get_auditkey(self):
        akey_list = []
        for key in self.get_raw_auditkey():
            if key:
                for record in key.data["keys"]:
                    if record not in akey_list:
                        akey_list.append(record.lower())
        return akey_list

    def get_raw_cmd(self):
        cmd_from_groups = []
        for group in self.get_groups():
            cmd_from_groups.append(group.cmd)
        return cmd_from_groups

    def get_cmd(self):
        cmd_list = []
        for command in self.get_raw_cmd():
            if command:
                for record in command.data["commands"]:
                    cmd = record["cmd"]
                    if isinstance(cmd,str):
                        cmd = cmd.lower()
                    if cmd not in cmd_list:
                        cmd_list.append(cmd)
        return cmd_list

    '''
    # Similar to get_job, dedups all of the commands inherited from groups
    def get_cmd(self):
        cmdlist = dict()
        for command in self.get_raw_cmd():
            if command:
                for cmd in command.data["commands"]:
                    cmd['priority'] = command.priority
                    key = (cmd['cmd'])
                    if key not in cmdlist or cmdlist[key]['priority'] < cmd['priority']:
                        cmdlist[key] = cmd
        command = list(cmdlist.values())
        return command
    '''

    def find_or_create_agent(self, group=[], commit=False, **kwargs):
        '''Find or Create Agent and optionally add to groups'''
        agent = Agent.query.get(self.aid)
        if not agent:
            agent = Agent(**kwargs)
        if group:
            if not isinstance(group,list):
                group = [group]
            for each in group:
                agent.groups.append(each)
        db.session.add(agent)
        if commit:
            db.session.commit()
        return agent

class GroupOps():
    def __init__(self, name):
        self.name = name

    def get_agents(self, execute=True):
        q=Group.query.filter(Group.name == self.name).first()
        if q:
            if execute:
                return q.agents.all()
            return q.agents
        return []

    def has_agent(self,aid):
        q=self.get_agents(execute=False).filter(Agent.id == aid).first()
        if q:
            return True
        return False

    def get_job(self):
        q=Group.query.filter(Group.name == self.name).first()
        if q:
            return q.job
        return []

    def has_job(self,name):
        job = self.get_job()
        if job and name == job.name:
            return True
        return False

    def old_agents(self):
        agents_not_updated = []
        group = Group.query.filter(Group.name == self.name).first()

        for agent in self.get_agents(execute=True):
            if agent.version < group.agentversion:
                agents_not_updated.append(agent)
        return agents_not_updated

    def find_or_create_group(self, label,agentversion,job_data=None, cmd_data=None, commit=False):
        '''Add Group'''
        group = Group.query.filter(Group.name == self.name).first()
        if not group:
            group = Group(name=self.name, label=label,agentversion=agentversion)
        if job_data:
            group.job = job_data
        if cmd_data:
            group.cmd = cmd_data
        db.session.add(group)
        if commit:
            db.session.commit()
        return group

class JobOps():
    def __init__(self, name):
        self.name = name

    def find_or_create_job(self,data,priority, commit=False):
        """ Find existing job or create new job """
        job = Job.query.filter(Job.name == self.name).first()
        if not job:
            job = Job(name=self.name,data=data,priority=priority)
            db.session.add(job)
            if commit:
                db.session.commit()
        return job

class AgentCmdOps():
    def __init__(self, name):
        self.name = name

    def find_or_create_agentcmd(self, data,priority, commit=False):
        """ Find existing agentcmd or create new agentcmd """
        agentcmd = AgentCmd.query.filter(AgentCmd.name == self.name).first()
        if not agentcmd:
            agentcmd = AgentCmd(name=self.name, data=data,priority=priority)
            db.session.add(agentcmd)
            if commit:
                db.session.commit()
        return agentcmd

class ScanOps():
    def __init__(self):
        pass

    def get_scan(self,name):
        '''Get scan by name'''
        pass

    def get_recent_scan(self):
        '''Get the most recent scan'''
        pass

    def get_recent_scan_for_ip(self):
        '''Get the most recent scan for ip'''
        pass

    def get_recent_scan_for_host(self):
        '''Get the most recent scan for host'''
        pass

    def get_history_for_ip(self):
        '''Get history for ip'''
        pass

    def get_history_for_host(self):
        '''Get history for host'''
        pass

    def get_history_for_host(self):
        '''Get history for host'''
        pass

class ADOps():
    def __init__(self):
        pass

    def build_metrics(self,group):
        '''Build metrics from a group'''
        pass
        # derivative users, computers and groups
        # membership to high value group
        # privileged asset

    def members(self,group,tree=True,startswith=False,bysid=False):
        '''Builds a tree JSON format from a group for D3 Flare'''
        dataset = []
        parent = {}
        total_users = 0
        total_computers = 0
        total_groups = 0
        def enum(group,parent_id=0,id=0):
            nonlocal parent
            nonlocal total_users
            nonlocal total_computers
            nonlocal total_groups

            if startswith:
#                g = ADGroup.query.filter(func.lower(ADGroup.cn)==func.lower(group)).order_by(ADGroup.id.desc()).first()
                search = "%{}%".format(group.lower())
                g = ADGroup.query.filter(ADGroup.name.ilike(search)).order_by(ADGroup.id.desc()).first()
            elif bysid:
                g = ADGroup.query.filter(ADGroup.objectsid == group).order_by(ADGroup.id.desc()).first()
            else:
                g = ADGroup.query.filter(func.lower(ADGroup.name)==func.lower(group)).order_by(ADGroup.id.desc()).first()
            if g and g.members:
                if parent_id == 0:
                    parent_id = g.id
                    id = g.id
                    parent = {"id":g.id,"parent_id":0,"name":g.name,"meta":{"object":g.objectclass}}
                id += 1
                for objclass,data in g.members.items():
                    if objclass in ("user","computer"):
                        for name in data["list"]:
                            if objclass == "user":
                                total_users += 1
                            elif objclass == "computer":
                                total_computers += 1
                            dataset.append({"id":.1,"parent_id":parent_id,"name":name,"meta":{"object":objclass}})
                    elif objclass in ("group"):
                        for name in data["list"]:
                            total_groups += 1
                            id += 1
                            dataset.append({"id":id,"parent_id":parent_id,"name":name,"meta":{"object":objclass}})
                            enum(name,parent_id=id,id=id)
        enum(group)
        if dataset:
            parent["meta"]["total_users"] = total_users
            parent["meta"]["total_computers"] = total_computers
            parent["meta"]["total_groups"] = total_groups
            dataset.append(parent)

        if tree:
            return self.build(dataset)
        return dataset

    def membership(self,asset,tree=True):
        dataset = []

        def enum(asset,parent_id=0,id=0):
            g = self.find(asset,as_object=True)
            if g:
                if g.name.lower() == asset.lower():
                    if parent_id == 0:
                        parent_id = g.id
                        id = g.id
                        dataset.append({"id":g.id,"parent_id":0,"name":g.name,"meta":{"object":g.objectclass}})
                    id += 1
                    for member in g.memberof["list"]:
                        id += 1
                        dataset.append({"id":id,"parent_id":parent_id,"name":member,"meta":{"object":"group"}})
                        enum(member,parent_id=id,id=id)
        enum(asset)

        if len(dataset) == 1:
            s = dataset[0]
            dataset[0]["children"] = [{"name":"No Membership","id":.1,"parent_id":s["id"],"meta":{"object":"none"}}]

        if tree:
            return self.build(dataset)
        return dataset

    def graph_find(self,asset):
        dataset = []
        g = self.find(asset,as_object=True)
        if g:
            dataset.append({"id":g.id,"children":[{"name":"Object:{}".format(g.objectclass),
                "id":.1,"parent_id":g.id,"meta":{"object":g.objectclass}}],"parent_id":0,"name":g.name,
                "meta":{"object":g.objectclass}}
            )
        return dataset

    def build(self,dataset):
        levels = {}
        for n in dataset:
            levels.setdefault(n['parent_id'], []).append(n)
        def build_tree(parent_id=0):
            nodes = [dict(n) for n in levels.get(parent_id, [])]
            for n in nodes:
                children = build_tree(n['id'])
                if children: n['children'] = children
            return nodes
        tree = build_tree()
        return tree

    def find(self,asset,as_object=False):
        asset = asset.lower()

        #user
        user = db.session.query(ADUser).filter(func.lower(ADUser.name) == asset).order_by(ADUser.id.desc()).first()
        if user:
            if as_object:
                return user
            return user.__dict__

        #group
        group = db.session.query(ADGroup).filter(func.lower(ADGroup.name) == asset).order_by(ADGroup.id.desc()).first()
        if group:
            if as_object:
                return group
            return group.__dict__

        #computer
        computer = db.session.query(ADComputer).filter(func.lower(ADComputer.name) == asset).order_by(ADComputer.id.desc()).first()
        if computer:
            if as_object:
                return computer
            return computer.__dict__

        return None
