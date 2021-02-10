from logging.handlers import RotatingFileHandler
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_migrate import Migrate, MigrateCommand
from flask_user import UserManager
from flask_script import Manager
import os,sys
import logging
from datetime import datetime as dt
from app.utils.flask_logs import LogSetup
import json

db = SQLAlchemy()
logs = LogSetup()
mail = Mail()
migrate = Migrate()

def create_app():
    # Instantiate Flask
    app = Flask(__name__)

    # Load common settings
    app.config.from_object('app.settings')
    # Load environment specific settings
    app.config.from_object('app.local_settings')

    # Setup Flask-SQLAlchemy
    db.init_app(app)

    # Add Jinja filter
    app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

    def to_pretty_json(value):
        return json.dumps(value,indent=4)

    app.jinja_env.filters['tojson_pretty'] = to_pretty_json

    # Add all models
    all_models = {}
    classes, models, table_names = [], [], []
    for clazz in db.Model._decl_class_registry.values():
        try:
            table_names.append(clazz.__tablename__)
            classes.append(clazz)
        except:
            pass
    for table in db.metadata.tables.items():
        if table[0] in table_names:
            all_models[table[0]] = classes[table_names.index(table[0])]
            models.append(classes[table_names.index(table[0])])
    app.models = all_models

    # Setup Flask-Migrate
    migrate.init_app(app, db)

    # Setup Flask-Mail
    mail.init_app(app)

    # Setup bootstrap
    init_bootstrap(app)

    # Register Blueprints
    from app.main import rest as main_api_bp
    from app.main import ui as main_ui_bp

    app.register_blueprint(main_api_bp,url_prefix='/api/main')
    app.register_blueprint(main_ui_bp,url_prefix='/ui')

    from app.agent import rest as agent_api_bp
    from app.agent import ui as agent_ui_bp

    app.register_blueprint(agent_api_bp,url_prefix='/api/agent')
    app.register_blueprint(agent_ui_bp,url_prefix='/ui')

    from app.ad import rest as ad_api_bp
    from app.ad import ui as ad_ui_bp

    app.register_blueprint(ad_api_bp,url_prefix='/api/ad')
    app.register_blueprint(ad_ui_bp,url_prefix='/ui')

    # User invitation
    from .models import User, UserInvitation

    # Setup Flask-User
    user_manager = UserManager(app, db, User, UserInvitationClass=UserInvitation)

    @app.context_processor
    def context_processor():
        return dict(user_manager=user_manager)

    # Setup Logging
    register_logger(app)

    @app.after_request
    def after_request(response):
        """ Logging after every request. """
        logger = logging.getLogger("app.access")
        logger.info(
            "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
            dt.utcnow().strftime("%d-%b-%Y:%H:%M:%S.%f")[:-3],
            request.remote_addr,
            request.method,
            request.path,
            request.scheme,
            response.status,
            response.content_length,
            request.referrer,
            request.user_agent,
            request.query_string
        )
        return response

    return app

def init_bootstrap(app):
    from flask_bootstrap import Bootstrap
    from flask_babelex import Babel

    # Initialize Flask-BabelEx
    babel = Babel(app)

    # Initialize Bootstrap
    bootstrap = Bootstrap(app)

def register_logger(app):
    logs.init_app(app)

from app import models
