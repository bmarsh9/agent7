from flask import session,current_app
from rq.compat import as_text, decode_redis_hash
from app.utils.formatmsg import msg_to_json
from rq import Queue
from rq.job import Job as rq_Job
import pickle
import zlib
import json
import operator

class RqQuery():
    '''
    .Description: Helper functions to deal with RQ tasks
    '''
    def __init__(self):
        self.queues_dict = current_app.queues

    def get_scheduled_jobs(self,job_id=None):
        # Retrieving scheduled jobs with rq scheduler
        job_list = []
        id_list = []
        id_seen = []
        key_list = ["description","meta","started_at","_status",
            "_id","failure_ttl","origin","enqueued_at","timeout",
            "ended_at","_result","created_at","result_ttl","ttl"]
        for name,scheduler in self.queues_dict.items():
            for job in scheduler.get_jobs(with_times=True):
                temp = {}
                job_obj = job[0]
                if job_obj._id not in id_seen:
                    id_seen.append(job_obj._id)
                    for key,value in vars(job_obj).items():
                        if key in key_list:
                            temp[key] = str(value)
                    job_list.append(temp)
        if job_id:
            for job in job_list:
                if job["_id"] == str(job_id):
                    return job
            return None
        return job_list

    def cancel(self,job_id):
        # Cancel a job in rq-scheduler
        for name,scheduler in self.queues_dict.items():
            if job_id in scheduler:
                if scheduler.cancel(job_id) is None:
                    return msg_to_json("Successfully cancelled scheduled job.",True,"success")
        return msg_to_json("Could not cancel scheduled job. It likely does not exist.")

    def delete(self,queue):
        # Emptying a queue, this will delete all jobs in this queue
        for name,scheduler in self.queues_dict.items():
            if queue == name:
                scheduler.empty()

        # Deleting a queue
        #q.delete(delete_jobs=True) # Passing in `True` will remove all jobs in the queue
        # queue is now unusable. It can be recreated by enqueueing jobs to it.

    def get_redis_jobs(self,job_id="*", queue=None, job_name=None, filter=[]):
        '''
        Get all jobs in redis. This will not return jobs that are scheduled with rq-scheduler
        because it does not put it into the rq worker queue until execution time
        .Example:
            result = RqQuery().get_redis_jobs(
                job_name="bloodhound_job",
                queue="ad-tasks",
                filter=[("status","ne","failed"),("origin","eq","ad-tasks")]
            )
        '''

        def to_filter(dict,filter):
            '''
            operator list:
                eq for ==
                in for in
                le for <=
                ge for >=
            .filter --> [("status","ne","failed"),("origin","eq","ad-tasks")]
            '''
            op_table = {
                "eq":operator.eq,
                "gt":operator.gt,
                "lt":operator.lt,
                "ge":operator.ge,
                "le":operator.le,
                "ne":operator.ne,
                "cn":operator.contains
            }
            for raw in filter:
                try:
                    key, op, value = raw
                except ValueError:
                    raise Exception('Invalid filter: %s' % raw)
                if not op_table[op](dict[key],value): #// if filter does not match, return false
                    return False
            return True

        job_ids = current_app.redis.keys('rq:job:'+job_id)

        test_list = []
        id_list = []
        for job_id in job_ids:
            temp_dict = decode_redis_hash(current_app.redis.hgetall(job_id))
            _id = job_id.replace('rq:job:', '')

            if _id not in id_list:
                temp_dict["job_id"] = _id
                test_list.append(temp_dict)
                id_list.append(_id)

        #// Add scheduled jobs
        try:
            for job in self.get_scheduled_jobs():
                test_list.append(job)
        #// Exception occurs when trying to gather scheduled tasks when a task is running
        except Exception as e:
            #logger e
            pass

        jobs = []
        for obj in test_list:
            if len(obj) == 0:
                pass
            if queue is not None:
                if queue != as_text(obj.get('origin')):
                    # If a specific queue was requested and this job isn't it, don't
                    # process the details of this job and don't return the job.
                    continue
            if job_name is not None:
                if job_name not in as_text(obj.get('description')):
                    continue

            #// Parse job object
            dict = self.parse_rq_obj(obj)

            #// Filter dictionary
            if filter:
                if to_filter(dict,filter) is not True: #// dictionary doesnt match filter query, reset loop
                    continue
            jobs.append(dict)
        return {"data":jobs,"count":len(jobs)}

    def parse_rq_obj(self,obj):
            raw_exc_info = obj.get('exc_info')
            try:
                exc_info = as_text(zlib.decompress(raw_exc_info))
            except Exception as e:
                # Fallback to uncompressed string
                # logger e
                exc_info = None
            dict = {
                'job_id': obj.get("job_id"),
                'created_at': str(obj.get('created_at')),
                'origin': as_text(obj.get('origin')),
#                'data': unpickle(obj.get('data')),
                'description': as_text(obj.get('description')),
                'enqueued_at': str(as_text(str(obj.get('enqueued_at')))),
                'ended_at': as_text(str(obj.get('ended_at'))),
                'result': self.unpickle(obj.get('result')) if obj.get('result') else None,  # noqa
                'exc_info': exc_info,
                'timeout': int(obj.get('timeout')) if obj.get('timeout') else None,
                'result_ttl': int(obj.get('result_ttl')) if obj.get('result_ttl') else None,  # noqa
                'status': as_text(obj.get('status') if obj.get('status') else None),
                'dependency_id': as_text(obj.get('dependency_id', None)),
                'meta': self.unpickle(obj.get('meta')) if obj.get('meta') else {},
                'scheduled_time': str(obj.get("scheduled_time",None))
            }
            return dict

    def to_date(self,date_str):
            if date_str is None:
                return
            else:
                return utcparse(as_text(date_str))

    def unpickle(self,pickled_string):
            try:
                obj = pickle.loads(pickled_string)
            except Exception as e:
                obj = None
                pass
#                raise UnpickleError('Could not unpickle.', pickled_string, e)
            return obj
