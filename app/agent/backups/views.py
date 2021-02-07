from app import create_app, db
from app.models import dbAgent,dbAgentTask,dbUser
from sqlalchemy import *
from datetime import datetime,timedelta

def panel_view(panel_id,graph_type):
    """
    .Description - return data to populate front end dashboards and panels
    .panel_id - each panel id has a different query
    .graph_type - (datatables or chartjs) returns data in a specific format
    """

    offset = timedelta(hours=72)
    delta = datetime.now() - offset

    #// Data structure for datatables
    returned_data = {"draw":0,"data": []}

    #// Panel ID's and graph types
    if panel_id == "0100":
        results = db.session.query(func.count(AgentId.id).label('count'),AgentId.os).\
            filter(AgentId.last_checkin<delta).group_by(AgentId.os).all()
        if graph_type == "chartjs":
            return results
        elif graph_type == "datatables":
            for record in results:
                returned_data["data"].append([record.aid,record.hostname,record.last_checkin])
            return returned_data
    elif panel_id == "0101":
        results = db.session.query(AgentId.id).filter(AgentId.last_checkin<delta).count()
        if graph_type == "chartjs":
            return results
    elif panel_id == "0102":
        results = db.session.query(func.count(AgentId.aid).label('count'),AgentId.sysmon_status).\
            filter(AgentId.last_checkin<delta).\
            group_by(AgentId.sysmon_status).all()
        if graph_type == "chartjs":
            return results
    elif panel_id == "0103":
        results = db.session.query(func.count(AgentId.aid).label('count'),AgentId.winlogbeat_status).\
            filter(AgentId.last_checkin<delta).\
            group_by(AgentId.winlogbeat_status).all()
        if graph_type == "chartjs":
            return results
    elif panel_id == "0104":
        results = db.session.query(func.count(AgentId.aid).label('count'),AgentId.groupname).\
            group_by(AgentId.groupname).all()
        if graph_type == "chartjs":
            return results
    elif panel_id == "0105":
        results = db.session.query(func.count(AgentTask.id).\
            label('count'),AgentTask.status).\
            group_by(AgentTask.status).all()
        if graph_type == "chartjs":
            results_json = {}
            for record in results:
                if record.status == "complete":
                    results_json["complete"] = record.count
                if record.status == "grabbed":
                    results_json["grabbed"] = record.count
                if record.status == "staged":
                    results_json["staged"] = record.count
            return results_json
    elif panel_id == "0106":
        offset = timedelta(hours=24)
        delta = datetime.now() - offset
        results = AgentId.query.filter(AgentId.last_checkin<delta).all()

        if graph_type == "datatables":
            for record in results:
                returned_data["data"].append([record.aid,record.hostname,record.last_checkin])
            return returned_data

    elif panel_id == "0107":
        results = db.session.query(func.count(AgentTask.status).\
            label('count'),AgentTask.status,AgentTask.taskname,AgentTask.id).\
            group_by(AgentTask.taskname,AgentTask.id,AgentTask.status).\
            order_by(AgentTask.id.desc())

        if graph_type == "datatables":
            data = [r._asdict() for r in results]
            temp = {}
            for d in data:
                if d["taskname"] not in temp:
                    temp[d["taskname"]] = {} 
                temp_d = temp[d["taskname"]]
                if d["status"] == "staged":
                    temp_d["one_count"] = temp_d.get("one_count",0) + int(d["count"])
                elif d["status"] == "grabbed":
                    temp_d["two_count"] = temp_d.get("two_count",0) + int(d["count"])
                elif d["status"] == "complete":
                    temp_d["three_count"] = temp_d.get("three_count",0) + int(d["count"])
                temp_d["total"] = temp_d.get("total",0) + int(d["count"])
                temp_d["id"] = d["id"]
            for key,value in temp.items():
                returned_data["data"].append([str(value["id"]),key,value["total"],100 * float(value.get("three_count",0)) / float(value["total"])])
            return returned_data
    elif panel_id == "0108":
        results = AgentTask.query.limit(1000)
        if graph_type == "datatables":
            for agent in results:
                display_threathunt = "%s->%s->%s->%s" % (agent.task["plugins"]["threathunt"]["category"],agent.task["plugins"]["threathunt"]["subcategory"],
                                                    agent.task["plugins"]["threathunt"]["fulldata"],agent.task["plugins"]["threathunt"]["enabled"])
                returned_data["data"].append([agent.id,agent.aid,agent.taskname,agent.tracking_id,agent.task["plugins"]["sysmon"]["task"],
                    agent.task["plugins"]["winlogbeat"]["task"],display_threathunt,agent.status])
            return returned_data
    elif panel_id == "0109":
        results = AgentId.query.limit(1000)
        if graph_type == "datatables":
           for agent in results:
               returned_data["data"].append([agent.id,agent.aid,agent.groupname,agent.hostname,agent.domain,agent.os,agent.sysmon_status,
                   agent.winlogbeat_status,agent.last_checkin,agent.install_date])
           return returned_data
