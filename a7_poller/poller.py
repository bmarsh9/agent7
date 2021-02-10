import json
import os
import sys
import time
from config import Config
import jobs as schjobs
import arrow
import logging

class Poller():
    def __init__(self,app):
        self.Tasks = app.tables["tasks"]

    def run(self):
        while True:
            time.sleep(1)
            for task in self.ready_to_run():
                logging.info("Executing ready task: {}".format(task.module))
                self.was_executed(task)
                args = task.args or {}
                try:
                    result = getattr(schjobs,task.module)(task,app,**args)
                except Exception as e:
                    logging.error("Exception when processing job:{}. Error:{}".format(task.module,e))
                    result = None
                if result:
                    task.healthy = True
                else:
                    task.healthy = False
                app.db_session.commit()

    def ready_to_run(self):
        tasks = []
        now = arrow.utcnow()
        enabled_tasks = app.db_session.query(self.Tasks).filter(self.Tasks.enabled == True).all()
        for task in enabled_tasks:
            if task.module:
                if not task.last_ran: # never ran
                    if not task.start_on or now > arrow.get(task.start_on):
                        tasks.append(task)
                else:
                    minutes = task.run_every or 1
                    if arrow.get(task.last_ran).shift(minutes=minutes) < now:
                        tasks.append(task)
        return tasks

    def was_executed(self,task):
        now = arrow.utcnow().datetime
        task.last_ran = now
        app.db_session.commit()

    def get_next_run(self,humanize=False):
        minutes = task.run_every or 0
        if self.last_ran:
            next_run = arrow.get(self.last_ran).shift(minutes=minutes or 1)
        else:
            next_run = arrow.utcnow()
        if humanize:
            return next_run.humanize()
        return next_run

if __name__ == "__main__":
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)
    logging.info("Starting the poller")
    base_dir = os.path.abspath(os.path.dirname(__file__))
    app = Config(base_dir)

    # Start service
    Poller(app).run()
