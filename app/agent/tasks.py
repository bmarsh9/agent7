from rq import get_current_job
from app import db,create_app
from app.models import Tasks,AgentNet,AgentUser,AssetLedger,ADGroup
from datetime import datetime,timedelta
import uuid
import sys
import json
from app.utils.misc import lookup_ip
from app.utils.db_helper import DynamicQuery
from app.utils.pam_helper import PamHelper

app = create_app()
app.app_context().push()

def enrich_network_connections():
    try:
        job = get_current_job()
        if job:
            job_id = str(job.get_id())
            app.logger.info("Executing Job Name: enrich_network_connections. Job ID: {}".format(job_id))
            # Gather all un-enriched network connections and enrich ones with public ip address
            connections = AgentNet.query.filter(AgentNet.private == False).filter(AgentNet.lat == None).filter(AgentNet.family == "tcp").all()
            for c in connections:
                geo = lookup_ip(c.raddr)
                if geo: #make sure it is a global ip
                    c.country_code = geo.country_code
                    c.country_name = geo.country_name
                    c.region_name = geo.region_name
                    c.city_name = geo.city_name
                    c.lat = geo.latitude
                    c.long = geo.longitude
                    db.session.commit()

            # Update the task
            Tasks.update_task(job_id,100)
            app.logger.info("Finished enriching network connection data:{}.".format(job_id))

        return "ok"
    except:
        app.logger.error("Unhandled exception", exc_info=sys.exc_info())

def update_privilged_user_tables():
    try:
        job = get_current_job()
        if job:
            job_id = str(job.get_id())
            app.logger.info("Executing Job Name: update_privilged_user_tables. Job ID: {}".format(job_id))

            # Do Stuff
            for user in PamHelper().get_priv_users():
                user.is_priv = "1"
            for process in PamHelper().get_process_for_priv_users():
                process.is_priv = "1"
            for schtask in PamHelper().get_schtask_for_priv_users():
                schtask.is_priv = "1"
            for service in PamHelper().get_service_for_priv_users():
                service.is_priv = "1"
            for startup in PamHelper().get_startup_for_priv_users():
                startup.is_priv = "1"
            for logon in PamHelper().get_logon_for_priv_users():
                logon.is_priv = "1"
            for connection in PamHelper().get_connections_for_priv_users():
                connection.is_priv = "1"
            db.session.commit()

            # Update the task
            Tasks.update_task(job_id,100)
            app.logger.info("Finished updating privileged users. Job ID:{}.".format(job_id))

        return "ok"
    except:
        app.logger.error("Unhandled exception", exc_info=sys.exc_info())

def update_built_in_group_ledger_table():
    '''As new domains are added, we need to insert new built in groups.. domain admins@domain1.com, domain admins@domain2.com'''
    try:
        job = get_current_job()
        if job:
            job_id = str(job.get_id())
            app.logger.info("Executing Job Name: update_built_in_group_ledger_table. Job ID: {}".format(job_id))
            # Do Stuff
            all_groups = []
            well_known_sid = ["-512","-519","-549","-550","-518","-544","-551"]
            for sid in well_known_sid:
                seen = []
                search = "%{}".format(sid)
                g = ADGroup.query.filter(ADGroup.objectsid.like(search)).order_by(ADGroup.id.desc()).all()
                for group in g:
                    if group.objectsid not in seen:
                        all_groups.append(group)
                        seen.append(group.objectsid)

            for group in all_groups:
                exists = AssetLedger.query.filter(AssetLedger.name == group.name).first()
                if not exists:
                    a = AssetLedger(name=group.name,objectclass="group")
                    db.session.add(a)
            db.session.commit()
            # Update the task
            Tasks.update_task(job_id,100)
            app.logger.info("Finished updating built in group ledger table. Job ID:{}.".format(job_id))

        return "ok"
    except:
        app.logger.error("Unhandled exception", exc_info=sys.exc_info())

def test_alert():
    try:
        job = get_current_job()
        if job:
            job_id = str(job.get_id())
            app.logger.info("Executing Job ID: {}".format(job_id))
            # Do Stuff

            # Update the task
            Tasks.update_task(job_id,100)


        return "ok"
    except:
        app.logger.error("Unhandled exception", exc_info=sys.exc_info())

