from flask import Blueprint

ui = Blueprint('agent_ui', __name__)
rest = Blueprint('agent_api', __name__)

from app.agent import routes,api


