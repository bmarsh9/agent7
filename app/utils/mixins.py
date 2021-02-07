class AgentMixin(object):
    def inc_host(self):
        self.host_name = self.agentname.hostname
        return self
