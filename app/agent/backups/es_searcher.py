from elasticsearch import Elasticsearch
import elasticsearch
from utils import *
from datetime import datetime,timedelta
import json

es = Elasticsearch()

# ----------------------------------------------- Raw Log Section -----------------------------------------------------
def raw_logs(aid="*",agent_taskname="*",query_string="*",start=str(),end=str(),size=10,view="default",agg_field=str(),fields=["*"]):
    return "raw logs"

# ----------------------------------------------- WMI Data Section -----------------------------------------------------
def win32_process(aid="*",agent_taskname="*",query_string="*",start=str(),end=str(),size=10,view="default",agg_field=str(),fields=["*"]):
    if view == "aggs":
        if not agg_field:
            agg_field="CommandLine.keyword"
        results = func_generate_agg(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_process",start=start,end=end,size=size,agg_field=agg_field)

    elif view == "default":
        results = raw_search(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_process",start=start,end=end,size=size,fields=fields)

    return results

def win32_service(aid="*",agent_taskname="*",query_string="*",start=str(),end=str(),size=10,view="default",agg_field=str(),fields=["*"]):
    if view == "aggs":
        if not agg_field:
            agg_field="DisplayName.keyword"
        results = func_generate_agg(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_service",start=start,end=end,size=size,agg_field=agg_field)

    elif view == "default":
        results = raw_search(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_service",start=start,end=end,size=size,fields=fields)

    return results

def win32_computersystem(aid="*",agent_taskname="*",query_string="*",start=str(),end=str(),size=10,view="default",agg_field=str(),fields=["*"]):
    if view == "aggs":
        if not agg_field:
            agg_field="Domain.keyword"
        results = func_generate_agg(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_computersystem",start=start,end=end,size=size,agg_field=agg_field)

    elif view == "default":
        results = raw_search(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_computersystem",start=start,end=end,size=size,fields=fields)

    return results

def win32_useraccount(aid="*",agent_taskname="*",query_string="*",start=str(),end=str(),size=10,view="default",agg_field=str(),fields=["*"]):
    if view == "aggs":
        if not agg_field:
            agg_field="Name.keyword"
        results = func_generate_agg(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_useraccount",start=start,end=end,size=size,agg_field=agg_field)

    elif view == "default":
        results = raw_search(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_useraccount",start=start,end=end,size=size,fields=fields)

    return results

def win32_quickfixengineering(aid="*",agent_taskname="*",query_string="*",start=str(),end=str(),size=10,view="default",agg_field=str(),fields=["*"]):
    if view == "aggs":
        if not agg_field:
            agg_field="Caption.keyword"
        results = func_generate_agg(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_quickfixengineering",start=start,end=end,size=size,agg_field=agg_field)

    elif view == "default":
        results = raw_search(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_quickfixengineering",start=start,end=end,size=size,fields=fields)

    return results

def win32_group(aid="*",agent_taskname="*",query_string="*",start=str(),end=str(),size=10,view="default",agg_field=str(),fields=["*"]):
    if view == "aggs":
        if not agg_field:
            agg_field="Name.keyword"
        results = func_generate_agg(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_group",start=start,end=end,size=size,agg_field=agg_field)

    elif view == "default":
        results = raw_search(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_group",start=start,end=end,size=size,fields=fields)

    return results

def win32_loggedonuser(aid="*",agent_taskname="*",query_string="*",start=str(),end=str(),size=10,view="default",agg_field=str(),fields=["*"]):
    if view == "aggs":
        if not agg_field:
            agg_field="AccountType"
        results = func_generate_agg(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_loggedonuser",start=start,end=end,size=size,agg_field=agg_field)

    elif view == "default":
        results = raw_search(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_loggedonuser",start=start,end=end,size=size,fields=fields)

    return results

def win32_startupcommand(aid="*",agent_taskname="*",query_string="*",start=str(),end=str(),size=10,view="default",agg_field=str(),fields=["*"]):
    if view == "aggs":
        if not agg_field:
            agg_field="Name.keyword"
        results = func_generate_agg(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_startupcommand",start=start,end=end,size=size,agg_field=agg_field)

    elif view == "default":
        results = raw_search(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_startupcommand",start=start,end=end,size=size,fields=fields)

    return results

def win32_networkadapterconfiguration(aid="*",agent_taskname="*",query_string="*",start=str(),end=str(),size=10,view="default",agg_field=str(),fields=["*"]):
    if view == "aggs":
        if not agg_field:
            agg_field="MACAddress.keyword"
        results = func_generate_agg(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_networkadapterconfiguration",start=start,end=end,size=size,agg_field=agg_field)

    elif view == "default":
        results = raw_search(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_networkadapterconfiguration",start=start,end=end,size=size,fields=fields)

    return results

def win32_share(aid="*",agent_taskname="*",query_string="*",start=str(),end=str(),size=10,view="default",agg_field=str(),fields=["*"]):
    if view == "aggs":
        if not agg_field:
            agg_field="Name.keyword"
        results = func_generate_agg(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_share",start=start,end=end,size=size,agg_field=agg_field)

    elif view == "default":
        results = raw_search(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_share",start=start,end=end,size=size,fields=fields)

    return results

def win32_networkloginprofile(aid="*",agent_taskname="*",query_string="*",start=str(),end=str(),size=10,view="default",agg_field=str(),fields=["*"]):
    if view == "aggs":
        if not agg_field:
            agg_field="Name.keyword"
        results = func_generate_agg(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_networkloginprofile",start=start,end=end,size=size,agg_field=agg_field)

    elif view == "default":
        results = raw_search(aid=aid,agent_taskname=agent_taskname,query_string=query_string,subcategory="win32_networkloginprofile",start=start,end=end,size=size,fields=fields)

    return results

# ----------------------------------------------- Helper Section -----------------------------------------------------

def raw_search(aid="*",agent_taskname="*",subcategory="*",query_string="*",start=str(),end=str(),size=10,fields=["*"]):
    query = base_query(aid=aid,agent_taskname=agent_taskname,subcategory=subcategory,query_string=query_string,gt_timestamp=start,lt_timestamp=end,size=size,fields=fields)

    index="agent-wmi*"
    search = es.search(
        index=index, body=query)
#DEBUG QUERY
#    print query
#DEBUG QUERY

    data = []
    total_docs = search['hits']['total']
    count=0
    for record in search["hits"]["hits"]:
        count+=1
        data.append(record["_source"])
    return data

#def func_generate_agg(agg_field,aid="*",agent_taskname="*",start=str(),end=str(),size=10):
def func_generate_agg(aid="*",agent_taskname="*",subcategory="*",query_string="*",start=str(),end=str(),size=10,fields=["*"],agg_field=str()):
    '''
    Function to generate an aggregation for field name
    '''
#    query = base_query(aid=aid,agent_taskname=agent_taskname,gt_timestamp=start,lt_timestamp=end)
    query = base_query(aid=aid,agent_taskname=agent_taskname,subcategory=subcategory,query_string=query_string,gt_timestamp=start,lt_timestamp=end,size=size,fields=fields)

    query["aggs"] = {
        "2": {
          "terms": {
             "field": agg_field,
             "size": size,
             "order": {
              "_count": "desc"
             }
          }
        }
    }

    index="agent-wmi*"
    template = "An exception of type {0} occurred. Arguments:\n{1!r}"
    try:
        search = es.search(
            index=index, body=query)
    except elasticsearch.RequestError as e:
        message = template.format(type(e).__name__, e.args)
        return {"message":message}
    except Exception as e:
        message = template.format(type(e).__name__, e.args)
        return {"message":message}
#haaaa
    return search["aggregations"]["2"]["buckets"]

def base_query(aid="*",agent_taskname="*",subcategory="*",query_string="*",gt_timestamp=str(),lt_timestamp=str(),size=10,fields=["*"]):
    '''
    Function that returns the base query, queries for AID, Taskname, and timestamps. This used by other functions to append additional queries to
    '''
    #// If timestamps arent set, default is 2 days of data
    if not gt_timestamp:
        offset = timedelta(hours=48)
        gt_timestamp = str((datetime.now() - offset).strftime("%Y-%m-%d"))
    if not lt_timestamp:
        lt_timestamp = str(datetime.now().strftime("%Y-%m-%d"))

    #// Generic Query
    query = {
#haaaa
      "version": "true",
      "size": size,
      "_source":fields,
      "query": {
        "bool": {
          "must": [
            {
              "range": {
                "agent_timestamp": {
                  "gte": "%s" % (gt_timestamp),
                  "lte": "%s" % (lt_timestamp),
                  "format": "yyyy-MM-dd||yyyy"
                }
              }
            }
          ],
          "filter": [
            {
              "bool": {
                "filter": [
                  {
                    "bool": {
                      "filter": [
                        {
                          "bool": {
                            "should": [
                              {
                                "query_string": {
                                  "fields": [
                                    "aid"
                                  ],
                                  "query": "%s" % aid
                                }
                              }
                            ],
                            "minimum_should_match": 1
                          }
                        },
                        {
                          "bool": {
                            "filter": [
                              {
                                "bool": {
                                  "should": [
                                    {
                                      "query_string": {
                                        "fields": [
                                          "agent_taskname"
                                        ],
                                        "query": "%s" % agent_taskname
                                      }
                                    }
                                  ],
                                  "minimum_should_match": 1
                                }
                              },
                              {
                                "bool": {
                                  "should": [
                                    {
                                      "query_string": {
                                        "fields": [
                                          "subcategory"
                                        ],
                                        "query": "%s" % subcategory
                                      }
                                    }
                                  ],
                                  "minimum_should_match": 1
                                }
                              }
                            ]
                          }
                        }
                      ]
                    }
                  },
                  {
                    "query_string": {
                      "query": "%s" % query_string
                    }
                  }
                ]
              }
            }
          ],
          "should": [],
          "must_not": []
        }
      }
    }
    return query


