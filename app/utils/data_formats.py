from flask import jsonify

def convert_to_datatables(data,fields=[]):
    data_dict = {"draw":0,"data": [],"count":0,"columns":[]}
    if not isinstance(data,list):
        data = [data]
    if not fields:
        fields = data[0].keys()
    for record in data:
        data_dict["count"] += 1
        temp_list = []
        for field in fields:
            try:
                temp_list.append(record[field])
                if field not in data_dict["columns"]:
                    data_dict["columns"].append(field)
            except KeyError:
                print("key: {%s} does not exist or restricted" % (field))
        data_dict["data"].append(temp_list)
    return jsonify(data_dict)

def convert_to_chartjs(data,fields=[]):
    dataset = {"count":0, "label":[], "data": [], "color": []}
    if not isinstance(data,list):
        data = [data]
    for record in data:
        dataset["count"] += 1
        for k,v in record.items():
            dataset["label"].append(k)
            dataset["data"].append(v)
    return dataset
