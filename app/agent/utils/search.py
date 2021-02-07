from flask import current_app
from datetime import datetime

def add_to_index(index, doc):
    if not current_app.elasticsearch:
        return
    payload = {}
#    for field in model.__searchable__:
#        payload[field] = getattr(model, field)
    index = "%s_%s" % (index,datetime.today().strftime('%Y-%m-%d'))
    current_app.elasticsearch.index(index=index, doc_type=index,
                                    body=doc)

def remove_from_index(index, model):
    if not current_app.elasticsearch:
        return
    current_app.elasticsearch.delete(index=index, doc_type=index, id=model.id)

def query_index(index, query_type, query, page, per_page):
    if not current_app.elasticsearch:
        return [], 0
    #// Raw search
    raw_search = "*exe"
    per_page = "500"
    if query_type == "raw":
        query = {
          "size": per_page,
          "query": {
            "bool": {
              "must": [
                {
                  "range": {
                    "agent_timestamp": {
                      "gte": "2016-05-04",
                      "lte": "2020-01-20",
                      "format": "yyyy-MM-dd||yyyy"
                    }
                  }
                }
              ],
              "filter": [
                {
                  "bool": {
                    "should": [
                      {
                        "query_string": {
                          "fields": [
                            "*"
                          ],
                          "query": raw_search
                        }
                      }
                    ],
                    "minimum_should_match": 1
                  }
                }
              ],
              "should": [],
              "must_not": []
            }
          }
        }
    elif query_type == "match":
        #// Match query
        query = {
          "size": per_page,
          "query": {
            "bool": {
              "must": [
                {
                  "match_phrase": {
                    "Status": {
                      "query": "OK"
                    }
                  }
                },
                {
                  "range": {
                    "agent_timestamp": {
                      "gte": "2016-05-04",
                      "lte": "2020-01-20",
                      "format": "yyyy-MM-dd||yyyy"
                    }
                  }
                }
              ],
              "filter": [
                {
                  "match_all": {}
                }
              ],
              "should": [],
              "must_not": []
            }
          }
        }
    search = current_app.elasticsearch.search(
        index=index, body=query)
#        body={'query': {'multi_match': {'query': query, 'fields': ['*']}},
#              'from': (page - 1) * per_page, 'size': per_page})
    for hit in search["hits"]["hits"]:
        print hit["_source"]
    ids = [hit['_id'] for hit in search['hits']['hits']]
#    ids = [int(hit['_id']) for hit in search['hits']['hits']]
    return ids, search['hits']['total']
