from flask import jsonify,current_app
from flask_login import current_user
from app.utils.decorators import login_required, roles_required
from app.ad import rest
from app import db
from app.models import ADGroup
from app.utils.operations import ADOps
from app.utils.ad_helper import ADHelper
from app.utils.data_formats import convert_to_datatables,convert_to_chartjs

@rest.route("/walk/<group>", methods=["GET","POST"])
@login_required
def walk_group(group="Domain Admins"):
    g = ADGroup.query.filter(ADGroup.cn==group).first()
    if g:
        users = g.members["user"]
        computers = g.members["computer"]
        groups = g.members["group"]

        for group in groups["list"]:
            sub_g = ADGroup.query.filter(ADGroup.cn==group).first()
            print(sub_g.members["group"])
        return "ok"
    return "not found"

@rest.route("/groups/members/users/<user>", methods=["GET","POST"])
@login_required
def ad_groups(group=None):
    g = ADGroup.query.filter(ADGroup.cn=="Domain Users").first()
    print(g.members)
    return "ok"

@rest.route("/users/memberof/<user>", methods=["GET","POST"])
@login_required
def ad_users_memberof(user=None):
    '''
    Get groups that a user is a member of
    '''
    pass

@rest.route("/privileged/users", methods=["GET"])
@login_required
def ad_priv_users():
    users = ADHelper().get_priv_users_format_1()
    fields = ['id','cn', 'disabled','active','service_account',
        'last_pwd_change', 'require_preauth', 'account_is_sensitive','logoncount', 'delegation',
        'des_key_only', 'password_encrypted', 'roastable', 'distinguishedname','non_exp_password','smartcard_required','lastlogon']
    return convert_to_datatables(users,fields=fields)

@rest.route("/pwd-last-changed", methods=["GET"])
@login_required
def ad_pwd_changed():
    users = ADHelper().password_last_changed_buckets()
    data = convert_to_chartjs(users)
    return jsonify(data)

