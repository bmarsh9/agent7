from flask import current_app

def get_table_object(table=None):
    if table is None:
        return current_app.models
    return current_app.models.get(table.lower())
