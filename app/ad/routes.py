from flask import Flask, request,url_for, render_template,redirect, flash, current_app,jsonify
from app.utils.decorators import login_required, roles_required
from app.models import ADSysvol,ADUser
from app import db
from app.ad import ui
from app.utils.operations import ADOps
import json

@ui.route('/sysvol', methods = ['GET'])
@login_required
def sysvol_view():
    return render_template("ad/sysvol_view.html")

@ui.route('/sysvol/file/<id>', methods = ['GET'])
@login_required
def sysvol_view_file(id):
    file = ADSysvol.query.get(id)
    return render_template("ad/sysvol_view_file.html",file=file)

@ui.route('/stale-users', methods = ['GET'])
@login_required
def stale_users():
    return render_template("ad/stale_users.html")

@ui.route('/stale-computers', methods = ['GET'])
@login_required
def stale_computers():
    return render_template("ad/stale_computers.html")

@ui.route('/stale-groups', methods = ['GET'])
@login_required
def stale_groups():
    return render_template("ad/stale_groups.html")

@ui.route('/attr-viewer', methods = ['GET','POST'])
@login_required
def attr_viewer():
    if request.method == "POST":
        r_asset = request.form.get("asset","None").strip()
        #asset = ADOps().find(r_asset)
        asset = ADUser.query.filter(ADUser.samaccountname == r_asset).first()
        if not asset:
            flash("Asset not found!", category="warning")
        else:
            asset = vars(asset)
        return render_template("ad/attr_viewer.html",asset=json.dumps(asset,default=str,indent=4))
    else:
        return render_template("ad/attr_viewer.html",asset=None)

@ui.route('/graph', methods = ['GET'])
@login_required
def graph():
    asset = request.args.get('asset',"Domain Admins")
    treeData = ADOps().members(asset)
    if not treeData:
        flash("Asset not found!",category="warning")
    help_message = "Displaying asset: {}".format(asset)
    return render_template("graphing.html",treeData=treeData,help_message=help_message)

@ui.route('/graph/members', methods = ['GET','POST'])
@login_required
def graph_members():
    asset = request.args.get('asset',"Domain Admins")
    treeData = ADOps().members(asset)
    if not treeData:
        flash("Asset is not a Group!",category="warning")
        return redirect(url_for("ad_ui.graph_find_asset",asset=asset))
    help_message = "Displaying members in the group: {}".format(asset)
    return render_template("graphing.html",treeData=treeData,help_message=help_message)

@ui.route('/graph/membership', methods = ['GET','POST'])
@login_required
def graph_membership():
    asset = request.args.get('asset',"Domain Admins")
    treeData = ADOps().membership(asset)
    if not treeData:
        flash("Asset not found!",category="warning")
    help_message = "Displaying group membership for the asset: {}".format(asset)
    return render_template("graphing.html",treeData=treeData,help_message=help_message)

@ui.route('/graph/find', methods = ['GET'])
@login_required
def graph_find_asset(asset=None):
    if not asset:
        asset = request.args.get('asset',"Domain Admins")
    treeData = ADOps().graph_find(asset)
    if not treeData:
        flash("Asset not found!",category="warning")
    help_message = "Displaying asset: {}".format(asset)
    return render_template("graphing.html",treeData=treeData,help_message=help_message)
