from flask import Blueprint,jsonify
from app.agent.views import *
from app.auth import *

blueprint_agent_ajax = Blueprint('blueprint_agent_ajax', __name__, template_folder='templates')

#----------------- AJAX --------------------#
@blueprint_agent_ajax.route("/ajax/<table_id>")
@login_required
def ajax_endpoint(table_id):
    '''
    Tables rendered in the HTML pages will make AJAX calls here for data
    '''
    if table_id == "0002": # error agents
        return jsonify(panel_view("0106","datatables"))

    elif table_id == "0003": # progress of agents per task
        return jsonify(panel_view("0107","datatables"))

    elif table_id == "0004": # show all tasks
        return jsonify(panel_view("0108","datatables"))

    elif table_id == "0005": # show agents in database
        return jsonify(panel_view("0109","datatables"))
