import ipaddress
import requests
import os
from sqlalchemy import or_

def enrich_network_connections(task,app,**kwargs):
    Table = app.tables["agentnet"]
    IpTable = app.tables["iplocation"]
    # Gather all un-enriched network connections and enrich ones with public ip address
    connections = app.db_session.query(Table).filter(or_(Table.private == False,Table.private == None)).filter(Table.lat == None).filter(Table.family == "tcp").all()
    for c in connections:
        try:
            if ipaddress.ip_address(c.raddr).is_global:
                address_dec = int(ipaddress.ip_address(c.raddr))
                geo = app.db_session.query(IpTable).filter(IpTable.ip_to > address_dec).filter(IpTable.ip_from < address_dec).first()
            else:
                geo = None
        except:
            geo = None
        if geo: #make sure it is a global ip
            c.country_code = geo.country_code
            c.country_name = geo.country_name
            c.region_name = geo.region_name
            c.city_name = geo.city_name
            c.lat = geo.latitude
            c.long = geo.longitude
            c.private == False
        else:
            c.lat = 0
            c.private = True
        app.db_session.commit()
    return True

def update_privilged_users(task,app,**kwargs):
    priv_map = [
        {"table":"agentnet","endpoint":"api/main/priv/connection"},
        {"table":"agentuser","endpoint":"api/main/priv/local-users"},
        {"table":"ad_user","endpoint":"api/main/priv/domain-users"},
        {"table":"agentservice","endpoint":"api/main/priv/service"},
        {"table":"agentprocess","endpoint":"api/main/priv/process"},
        {"table":"agentlogon","endpoint":"api/main/priv/logon"},
        {"table":"agentstartup","endpoint":"api/main/priv/startup"},
        {"table":"agentschtask","endpoint":"api/main/priv/schtask"}
    ]
    for each in priv_map:
        path = "{}/{}".format(app.agent7_url,each["endpoint"])
        r = requests.get(path,verify=False)
        if r.ok:
            data = r.json()["data"]
            Table = app.tables[each["table"]]
            for id in data:
                _query = app.db_session.query(Table).filter(Table.id == id).first()
                if _query:
                    _query.is_priv = "1"
                    app.db_session.commit()
    return True

def update_built_in_groups(task,app,**kwargs):
    GroupTable = app.tables["ad_group"]
    AssetTable = app.tables["asset_ledger"]
    all_groups = []
    well_known_sid = ["-512","-519","-549","-550","-518","-544","-551"]
    for sid in well_known_sid:
        seen = []
        search = "%{}".format(sid)
        g = app.db_session.query(GroupTable).filter(GroupTable.objectsid.like(search)).order_by(GroupTable.id.desc()).all()
        for group in g:
            if group.objectsid not in seen:
                all_groups.append(group)
                seen.append(group.objectsid)

    for group in all_groups:
        exists = app.db_session.query(AssetTable).filter(AssetTable.name == group.name).first()
        if not exists:
            a = AssetTable(name=group.name,objectclass="group")
            app.db_session.add(a)
    app.db_session.commit()
    return True
