from flask import Blueprint

ui = Blueprint('main_ui', __name__)
rest = Blueprint('main_api', __name__)

from app.main import routes,api
