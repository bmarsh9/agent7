class Dictionary():
    def __init__(self,model):
        self.model = model.strip()

    def get_fields(self):
        available_models = {
            "agentprocess":["host_id","pid","ppid"],
            "agentschtask":["host_id","command"],
            "agentnet":["host_id","pname","raddr","pid"],
            "agentservice":["host_id","image","command"],
            "agentmemory":["host_id"],
            "agentdisk":["host_id"],
            "agentpipe":["host_id","name"],
            "agentprinter":["host_id","name"],
            "agentpatch":["host_id","caption"],
            "agentlogon":["host_id","username","logonid"],
            "agentnetsession":["host_id","user_name","client_name"],
            "agentsoftware":["host_id","displayname"],
            "agentupdates":["host_id","guid"],
            "agentsystem":["host_id"],
            "agentshare":["host_id","name","path"],
            "agentstartup":["host_id","username","command"],
            "agentadapter":["host_id","caption"],
            "agentuser":["host_id","sid"],
            "agentgroup":["host_id","group","members_count"],
            "agentneighbor":["host_id","asset","address"],
            "agentscan":["host_id","asset","address","port"],
        }

        return available_models.get(self.model)

