from flask import Blueprint,jsonify,abort, request, url_for, render_template,redirect, session, flash, current_app,send_from_directory,send_file
from app.agent.search import add_to_index, remove_from_index, query_index

#// Imports
from app.auth import *
from app.agent.tasks import *
from app.agent.utils import *
from app.agent.views import *
from app.agent.es_searcher import *
#from app.models import BHElasticsearchModel

import shutil,jinja2,os,subprocess,json
from datetime import datetime,timedelta
from random import choice
from string import digits

app = create_app()
blueprint_agent_api = Blueprint('blueprint_agent_api', __name__, template_folder='templates')

@blueprint_agent_api.route('/api/agent/register', methods = ['POST','GET'])
@login_required
def new_agent():
    """
    Adding a new agent to the database
    """
    groupname = request.form.get('groupname','main')
    aid = ''.join(choice(digits) for i in range(30))
    token = ''.join(choice(digits) for i in range(30))

    if aid is None or token is None:
        return jsonify({"message":"400"})
    if AgentId.query.filter_by(aid = aid).first() is not None:
        return jsonify({"message":"400"})
    if groupname is None:
        groupname = "main"
    agent = AgentId(aid = aid,groupname=groupname)
    agent.hash_token(token)

    # ---- Generate agent install file ----
    #// Set Directories
    agent_dir = app.config["AGENT_DIR"]
    client_dir = os.path.join(agent_dir,"agentbuild","clients")
    dir_name = os.path.join(agent_dir,"agentbuild","windows")
    template_dir = os.path.join(agent_dir,"agentbuild","templates")

    output_filename = "honeyad_agent" #// Zip filename

    #// Render Agent Configuration file
    config_file = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir+"/")).\
        get_template("app.conf").\
        render(server="10.5.200.82",port=5000,aid=aid,token=token)

    #// Save the configuration file
    with open(os.path.join(dir_name,"app.conf"),"w") as file:
        config_file = config_file.encode('utf-8').strip()
        file.write(config_file)

    #// Create client certificate and move it into the zip directory
    with open(os.devnull, "w") as f:
        script_path = os.path.join(agent_dir,"certauth/create_certs.sh")
        subprocess.call(["/bin/bash",script_path,"client"],stdout=f,stderr=f)

    #// Zip the directory up
    full_zipfile_path = os.path.join(client_dir,output_filename)
    perform_zip = shutil.make_archive(full_zipfile_path, 'zip', dir_name)

    #// Check if file exists, add agent and return zip file
    if os.path.isfile(perform_zip):
        db.session.add(agent)
        db.session.commit()
        return send_file(perform_zip,attachment_filename="honeyad_agent.zip",as_attachment=True)

@blueprint_agent_api.route("/api/agent/orders",methods=["GET"])
@agent_login_required
def agent_orders():
    '''
    Function for agents to retrieve their orders and for users to input new orders for the agents
    '''
    aid = request.headers.get("aid")
    #// Agent calling in for their orders
    record = AgentTask.query.filter_by(aid=aid,status="staged").first() #// grab the task for the agent
    if record:
        update_record = AgentTask.query.filter_by(aid = aid, id=record.id).update({"status":"grab"}) #// update the status of the record to show agent got the task
        db.session.commit()
        data_returned = {"tracking_id":record.tracking_id,"message":record.task,"status":"ok","taskname":record.taskname,"aid":record.aid}
        return jsonify(data_returned)
    return jsonify({"status":"default"}) #// no tasks, run the default taskval

@blueprint_agent_api.route("/api/agent/file/<plugin>/<filetype>/<filename>")
@agent_login_required
def agent_download(plugin,filetype,filename):
    '''
    Function for agents to download new configuration and zip files
    '''
    valid_plugins = ["sysmon","winlogbeat"]
    valid_filetypes = ["exe","config"]
    if plugin in valid_plugins and filetype in valid_filetypes:
        grab_directory = "files/%s/%s/" % (plugin,filetype)
        return send_from_directory(grab_directory, filename)
    return "error"

@blueprint_agent_api.route("/api/agent/callback",methods=["POST"])
@agent_login_required
def agent_callback():
    '''
    Function for the agent to callback to and send data such as status updates and threat hunting data
    '''
    aid = request.headers.get("aid")
    #// Check agent hostname, platform, and domain
    record = AgentId.query.filter_by(aid=aid).first()
    if record.hostname is None or record.os is None or record.domain is None:
        AgentId.query.filter_by(aid=aid).update({"os":request.headers.get("Platform"),
            "hostname":request.headers.get("Hostname"),"domain":request.headers.get("Fqdn")})
        db.session.commit()

    response = request.get_json()
    if response:
        tracking_id = response["tracking_id"]
        if tracking_id == 100: #// default task
            sysmon_status = "Not Running"
            winlogbeat_status = "Not Running"
            if response["message"]["sysmon"] is True:
                sysmon_status = "Running"
            if response["message"]["winlogbeat"] is True:
                winlogbeat_status = "Running"
            update_record = AgentId.query.filter_by(aid = aid).update({"sysmon_status":sysmon_status,
                "winlogbeat_status":winlogbeat_status}) #// update the status of the record to show agent got the task
            db.session.commit()
        else: #// Update the tracking number and capture the data
            update_record = AgentTask.query.filter_by(tracking_id=tracking_id).update({"status":"complete"}) #// update the status of the record to show agent completed the task
            db.session.commit()
            #// Post data to ES
            if response.get('message', {}).get('threathunt', None):
                es_wmi_index = app.config["ELASTICSEARCH_WMI"]
                for data in response["message"]["threathunt"]:
                    for key, value in data.items():
                        response = ElasticsearchModel(es_wmi_index,"_doc").add_to_index(value)
#                        for record in value:
#                            try:
#                                add_to_index(es_wmi_index, record)
#                            except Exception as e:
#                                print e
    return jsonify({"task":"got it","message":"Ok","status":200})

@blueprint_agent_api.route("/api/agent/wmi",methods=["GET","POST"])
#@login_required
def wmi_returner():
    aid = request.args.get('aid', default = "*", type = str)
    taskname = request.args.get('taskname', default = "*", type = str)
    subcategory = request.args.get('subcategory', default = "*", type = str)
    size = request.args.get('size', default = 10, type = int)
    query_string = request.args.get('query_string', default = "*", type = str) #// returns a different view of the data
    start = request.args.get('start', default = str(), type = str)
    end = request.args.get('end', default = str(), type = str)
    fields = request.args.get('fields', default = ["*"], type = str)
    agg_field = request.args.get('agg_field', default = str(), type = str)
    view = request.args.get('view', default = "default", type = str) #// returns a different view of the data
    graph_format = request.args.get('graph_format', default = "datatables", type = str) #// returns the data in a way that can be read by the graph library (datatables,chartjs)
#haaaaa
    if "*" not in fields:
        try:
            fields = fields.split(",")
        except:
            fields = ["*"]

    wmi_subcategories = {
        'win32_computersystem': win32_computersystem,
        'win32_useraccount': win32_useraccount,
        'win32_quickfixengineering': win32_quickfixengineering,
        'win32_group': win32_group,
        'win32_service': win32_service,
        'win32_loggedonuser': win32_loggedonuser,
        'win32_process': win32_process,
        'win32_startupcommand': win32_startupcommand,
        'win32_share': win32_share,
        'win32_networkadapterconfiguration': win32_networkadapterconfiguration,
        'win32_networkloginprofile': win32_networkloginprofile
    }

    data = []
    if not subcategory or subcategory == "all": # return all data
        for subcategory in wmi_subcategories:
            data.append(wmi_subcategories[subcategory](aid=aid,agent_taskname=taskname,
                query_string=query_string,start=start,end=end,size=size,view=view,fields=fields,agg_field=agg_field))
    elif subcategory not in wmi_subcategories:
        return jsonify({"message":"invalid subcategory"})
    else:
        data.append(wmi_subcategories[subcategory](aid=aid,agent_taskname=taskname,
            query_string=query_string,start=start,end=end,size=size,view=view,fields=fields,agg_field=agg_field))
    return jsonify(data)
