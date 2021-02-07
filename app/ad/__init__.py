from flask import Blueprint

ui = Blueprint('ad_ui', __name__)
rest = Blueprint('ad_api', __name__)

from app.ad import routes,api
