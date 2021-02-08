# Settings common to all environments (development|staging|production)
# Place environment specific settings in env_settings.py
# An example file (env_settings_example.py) can be used as a starting point

import os

# Application settings
APP_NAME = "Agent 7"
APP_SYSTEM_ERROR_SUBJECT_LINE = APP_NAME + " system error"

# Settings
CONSOLE_VERSION = "1.0.0"
LICENSE = "Agent7"

# Special case for templates, display word in different colors
APP_TITLE_FIRST = "Agent"
APP_TITLE_LAST = " 7"

# Flask settings
#CSRF_ENABLED = True

# Flask-User settings
USER_APP_NAME = APP_NAME
USER_LOGIN_URL = '/'
USER_AFTER_LOGIN_ENDPOINT = 'main_ui.dashboard'
USER_AFTER_LOGOUT_ENDPOINT = 'user.login'
USER_CORPORATION_NAME = "Agent7"
USER_COPYRIGHT_YEAR = "2021"

USER_ENABLE_REGISTER = False
USER_ENABLE_USERNAME  = False
USER_ALLOW_LOGIN_WITHOUT_CONFIRMED_EMAIL = True
USER_EMAIL_SENDER_EMAIL = "admin@example.com"
USER_EMAIL_SENDER_NAME = "Admin"
USER_ENABLE_INVITE_USER = True
USER_REQUIRE_INVITATION = True
