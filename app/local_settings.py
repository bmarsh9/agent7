import os

BASEDIR = os.path.abspath(os.path.dirname(__file__))
AGENTDIR = os.path.join(BASEDIR,"app","agent")
INITDBDIR = os.path.join(BASEDIR,"commands")
# *****************************
# Environment specific settings
# *****************************

# DO NOT use "DEBUG = True" in production environments
DEBUG = True

# Restricted fields from Models
RESTRICTED_FIELDS = ["password"]

# Default Valid RTR commands
DEFAULT_CMD = {"commands": [
        {"cmd":"netstat"}
]}

# Default Job
DEFAULT_JOB = {"jobset": [
        {"task":"get-software","interval":86400,"force":0,"enabled":0},
        {"task":"get-updates","interval":86400,"force":0,"enabled":0},
        {"task":"get-connection","interval":500,"force":0,"enabled":0},
        {"task":"get-process","interval":400,"force":0,"enabled":0},
        {"task":"get-service","interval":43200,"force":0,"enabled":0},
        {"task":"get-patch","interval":86400,"force":0,"enabled":0},
        {"task":"get-user","interval":86400,"force":0,"filter":{'localaccount':False},"enabled":0},
        {"task":"get-group","interval":86400,"force":0,"filter":{'localaccount':False},"enabled":0},
        {"task":"get-system","interval":86400,"force":0,"enabled":0},
        {"task":"get-logon","interval":20,"force":0,"enabled":0},
        {"task":"get-netadapter","interval":86400,"force":0,"enabled":0},
        {"task":"get-share","interval":14400,"force":0,"enabled":0},
        {"task":"get-startup","interval":86400,"force":0,"enabled":0},
        {"task":"get-schtask","interval":1600,"force":0,"enabled":0},
        {"task":"get-memory","interval":14400,"force":0,"enabled":0},
        {"task":"get-disk","interval":86400,"force":0,"enabled":0},
        {"task":"get-printer","interval":86400,"force":0,"enabled":0},
        {"task":"get-pipe","interval":86400,"force":0,"enabled":0},
        {"task":"get-netsession","interval":600,"force":0,"enabled":0},
        {"task":"get-ad-user","interval":172800,"force":0,"enabled":0},
        {"task":"get-ad-group","interval":172800,"force":0,"enabled":0},
        {"task":"get-ad-computer","interval":172800,"force":0,"enabled":0},
        {"task":"get-ad-ou","interval":172800,"force":0,"enabled":0},
        {"task":"get-ad-gpo","interval":172800,"force":0,"enabled":0},
        {"task":"get-ad-sysvol","interval":172800,"force":0,"enabled":0},
        {"task":"get-ad-dc","interval":172800,"force":0,"enabled":0},
        {"task":"get-ad-domain","interval":172800,"force":0,"enabled":0},
        {"task":"get-platform","interval":300,"force":0,"enabled":1},
        {"task":"get-auditkeys","interval":172800,"force":0,"enabled":0},
        {"task":"set-localaccount","interval":600,"force":0,"enabled":0},
        {"task":"set-adaccount","interval":600,"force":0,"enabled":0},
]}

# DO NOT use Unsecure Secrets in production environments
# Generate a safe one with:
#     python -c "import os; print repr(os.urandom(24));"
SECRET_KEY = 'This is an UNSECURE Secret. CHANGE THIS for production environments.'
SITE_KEY = "737e079a-6170-4aae-91a6-60aca1f213aa"

SERVER_HOST = "localhost"

#// Customize
COMPANY = "agent7"

#// Postgres
SQLALCHEMY_DATABASE_URI = 'postgresql://db1:db1@postgres_db/db1'
SQLALCHEMY_TRACK_MODIFICATIONS = False

RMQ_USER = "guest"
RMQ_PASS = "guest"
RMQ_HOST = "rabbitmq"
RMQ_QUEUE = "agent7_queue"

# Logging Setup
LOG_TYPE = "watched"  # Default is a Stream handler
LOG_LEVEL = "INFO"

# File Logging Setup
LOG_DIR = "logs"
APP_LOG_NAME = "app.log"
WWW_LOG_NAME = "www.log"
LOG_MAX_BYTES = 100000000  # 100MB in bytes
LOG_COPIES = 5

# Flask-Mail settings
# For smtp.gmail.com to work, you MUST set "Allow less secure apps" to ON in Google Accounts.
# Change it in https://myaccount.google.com/security#connectedapps (near the bottom).
'''
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USE_SSL = False
MAIL_USE_TLS = True
MAIL_USERNAME = 'agent7'
MAIL_PASSWORD = 'agent7'
'''

# Sendgrid settings
SENDGRID_API_KEY='none'

ADMINS = [
    '"Admin One" <admin1@gmail.com>',
    ]
