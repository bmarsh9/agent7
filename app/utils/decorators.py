""" This module defines Flask-User decorators
such as @login_required, @roles_accepted and @roles_required and @confirmed_email_required.
"""
from functools import wraps
from flask import current_app, g, request, jsonify,redirect,url_for,session,flash
from app.models import User, Agent, Site
from app import db
from flask_login import current_user

def site_key_required(view_function):
    @wraps(view_function)    # Tells debuggers that is is a function wrapper
    def decorator(*args, **kwargs):
        #// Try to authenticate with an token (API login, must have site in HTTP header)
        key = request.headers.get("site-key")
        if key:
            #try:
                site = Site.query.filter(Site.key == key).first()
                if site:
                    return view_function(*args, **kwargs)
            #except Exception as e:
            #    print("Error while authenticating the site key:{}".format(e))
            #    pass
        return jsonify({"message":"authentication failed"}),401
    return decorator

def agent_auth(view_function):
    @wraps(view_function)    # Tells debuggers that is is a function wrapper
    def decorator(*args, **kwargs):
        #// Try to authenticate with an token (API login, must have token in HTTP header)
        aid = request.headers.get("aid")
        token = request.headers.get("token")
        if token and aid:
            #try:
                agent = Agent.query.filter(Agent.id == aid).filter(Agent.token == token).first()
                if not agent:
                    return jsonify({"message":"agent not registered"}),401
                if not agent.enabled:
                    return jsonify({"message":"agent disabled"}),403
                if agent:
                    return view_function(agentobj=agent,*args, **kwargs)
            #except Exception as e:
            #    print("Failed agent authentication - decorators:{}".format(e))
        return jsonify({"message":"authentication failed"}),401
    return decorator

def _is_logged_in_with_confirmed_email(user_manager):
    """| Returns True if user is logged in and has a confirmed email address.
    | Returns False otherwise.
    """
    # User must be logged in
    if user_manager.call_or_get(current_user.is_authenticated):
        # Is unconfirmed email allowed for this view by @allow_unconfirmed_email?
        unconfirmed_email_allowed = \
            getattr(g, '_flask_user_allow_unconfirmed_email', False)

        # unconfirmed_email_allowed must be True or
        # User must have at least one confirmed email address
        if unconfirmed_email_allowed or user_manager.db_manager.user_has_confirmed_email(current_user):
            return True

    return False

def validate_token_in_header(user_manager,enc_token):
    user = User.verify_auth_token(enc_token)
    if not user: # invalid token
        return False
    if not user.is_active:
        return False

    # Is unconfirmed email allowed for this view by @allow_unconfirmed_email?
    unconfirmed_email_allowed = \
        getattr(g, '_flask_user_allow_unconfirmed_email', False)
    # unconfirmed_email_allowed must be True or
    # User must have at least one confirmed email address
    if unconfirmed_email_allowed or user.email_confirmed_at:
        return user

    return False

def login_required_no_mfa(view_function):
    @wraps(view_function)    # Tells debuggers that is is a function wrapper
    def decorator(*args, **kwargs):
        user_manager = current_app.user_manager
        # User must be logged in with a confirmed email address
        allowed = _is_logged_in_with_confirmed_email(user_manager)
        if not allowed:
            # Redirect to unauthenticated page
            return user_manager.unauthenticated_view()
        # It's OK to call the view
        return view_function(*args, **kwargs)

    return decorator

def login_required(view_function):
    """ This decorator ensures that the current user is logged in.

    Example::

        @route('/member_page')
        @login_required
        def member_page():  # User must be logged in
            ...

    If USER_ENABLE_EMAIL is True and USER_ENABLE_CONFIRM_EMAIL is True,
    this view decorator also ensures that the user has a confirmed email address.

    | Calls unauthorized_view() when the user is not logged in
        or when the user has not confirmed their email address.
    | Calls the decorated view otherwise.
    """
    @wraps(view_function)    # Tells debuggers that is is a function wrapper
    def decorator(*args, **kwargs):
        user_manager = current_app.user_manager

        #// Try to authenticate with an token (API login, must have token in HTTP header)
        enc_token = request.headers.get("token")
        if enc_token:
            if not validate_token_in_header(user_manager,enc_token):
                return jsonify({"message":"authentication failed"}),401
        else: # Session authentication
            # User must be logged in with a confirmed email address
            allowed = _is_logged_in_with_confirmed_email(user_manager)
            if not allowed:
                # Redirect to unauthenticated page
                return user_manager.unauthenticated_view()

        # It's OK to call the view
        return view_function(*args, **kwargs)

    return decorator

def roles_accepted(*role_names):
    """| This decorator ensures that the current user is logged in,
    | and has *at least one* of the specified roles (OR operation).

    Example::

        @route('/edit_article')
        @roles_accepted('Writer', 'Editor')
        def edit_article():  # User must be 'Writer' OR 'Editor'
            ...

    | Calls unauthenticated_view() when the user is not logged in
        or when user has not confirmed their email address.
    | Calls unauthorized_view() when the user does not have the required roles.
    | Calls the decorated view otherwise.
    """
    # convert the list to a list containing that list.
    # Because roles_required(a, b) requires A AND B
    # while roles_required([a, b]) requires A OR B
    def wrapper(view_function):

        @wraps(view_function)    # Tells debuggers that is is a function wrapper
        def decorator(*args, **kwargs):
            user_manager = current_app.user_manager

            #// Try to authenticate with an token (API login, must have token in HTTP header)
            enc_token = request.headers.get("token")
            if enc_token:
                user = validate_token_in_header(user_manager,enc_token)
                if user:
                    current_user = user
                else:
                    return jsonify({"message":"authentication failed"}),401
            else:
                # User must be logged in with a confirmed email address
                allowed = _is_logged_in_with_confirmed_email(user_manager)
                if not allowed:
                    # Redirect to unauthenticated page
                    return user_manager.unauthenticated_view()

            # User must have the required roles
            # NB: roles_required would call has_roles(*role_names): ('A', 'B') --> ('A', 'B')
            # But: roles_accepted must call has_roles(role_names):  ('A', 'B') --< (('A', 'B'),)
            if not current_user.has_roles(role_names):
                if enc_token:
                    return jsonify({"message":"forbidden"}),403
                # Redirect to the unauthorized page
                flash("User does not have the required roles to access this resource!",category="danger")
                return redirect(url_for("main_ui.dashboard"))
#                return user_manager.unauthorized_view()

            # It's OK to call the view
            return view_function(*args, **kwargs)

        return decorator

    return wrapper


def roles_required(*role_names):
    """| This decorator ensures that the current user is logged in,
    | and has *all* of the specified roles (AND operation).

    Example::

        @route('/escape')
        @roles_required('Special', 'Agent')
        def escape_capture():  # User must be 'Special' AND 'Agent'
            ...

    | Calls unauthenticated_view() when the user is not logged in
        or when user has not confirmed their email address.
    | Calls unauthorized_view() when the user does not have the required roles.
    | Calls the decorated view otherwise.
    """
    def wrapper(view_function):

        @wraps(view_function)    # Tells debuggers that is is a function wrapper
        def decorator(*args, **kwargs):
            user_manager = current_app.user_manager
            #// Try to authenticate with an token (API login, must have token in HTTP header)
            enc_token = request.headers.get("token")
            if enc_token:
                user = validate_token_in_header(user_manager,enc_token)
                if user:
                    cu = user
                else:
                    return jsonify({"message":"authentication failed"}),401
            else:
                # User must be logged in with a confirmed email address
                allowed = _is_logged_in_with_confirmed_email(user_manager)
                if not allowed:
                    # Redirect to unauthenticated page
                    return user_manager.unauthenticated_view()

            # User must have the required roles
            if not current_user.has_roles(*role_names):
                if enc_token:
                    return jsonify({"message":"forbidden"}),403
                # Redirect to the unauthorized page
                flash("User does not have the required roles to access this resource!",category="danger")
                return redirect(url_for("main_ui.dashboard"))
#                return user_manager.unauthorized_view()

            # It's OK to call the view
            return view_function(*args, **kwargs)

        return decorator

    return wrapper



def allow_unconfirmed_email(view_function):
    """ This decorator ensures that the user is logged in,
    but allows users with or without a confirmed email addresses
    to access this particular view.

    It works in tandem with the ``USER_ALLOW_LOGIN_WITHOUT_CONFIRMED_EMAIL=True`` setting.

    .. caution::

        | Use ``USER_ALLOW_LOGIN_WITHOUT_CONFIRMED_EMAIL=True`` and
            ``@allow_unconfirmed_email`` with caution,
            as they relax security requirements.
        | Make sure that decorated views **never call other views directly**.
            Allways use ``redirect()`` to ensure proper view protection.


    Example::

        @route('/show_promotion')
        @allow_unconfirmed_emails
        def show_promotion():   # Logged in, with or without
            ...                 # confirmed email address

    It can also precede the ``@roles_required`` and ``@roles_accepted`` view decorators::

        @route('/show_promotion')
        @allow_unconfirmed_emails
        @roles_required('Visitor')
        def show_promotion():   # Logged in, with or without
            ...                 # confirmed email address

    | Calls unauthorized_view() when the user is not logged in.
    | Calls the decorated view otherwise.
    """
    @wraps(view_function)    # Tells debuggers that is is a function wrapper
    def decorator(*args, **kwargs):
        # Sets a boolean on the global request context
        g._flask_user_allow_unconfirmed_email = True

        # Catch exceptions to properly unset boolean on exceptions
        try:
            user_manager = current_app.user_manager

            # User must be logged in with a confirmed email address
            allowed = _is_logged_in_with_confirmed_email(user_manager)
            if not allowed:
                # Redirect to unauthenticated page
                return user_manager.unauthenticated_view()

            # It's OK to call the view
            return view_function(*args, **kwargs)

        finally:
            # Allways unset the boolean, whether exceptions occurred or not
            g._flask_user_allow_unconfirmed_email = False

    return decorator

