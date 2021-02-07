from flask import current_app
import pika
import json

class SQSHelper():
    def __init__(self):
        pass

    def send(self,model,payload):
        #Send message to SQS queue
        response = current_app.config["SQS_CONNECTION"].send_message(
            QueueUrl=current_app.config["SQS_QUEUE_URL"],
            DelaySeconds=0,
            MessageAttributes={
                'model': {
                  'DataType': 'String',
                  'StringValue': str(model)
                },
            },
            MessageBody=(payload)
        )
        return True

class RMQHelper():
    def __init__(self):
        pass

    def send(self,model,payload):
        credentials = pika.PlainCredentials(current_app.config["RMQ_USER"], current_app.config["RMQ_PASS"])
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(current_app.config["RMQ_HOST"],5672,"/",credentials))
        channel = connection.channel()

        queue = current_app.config["RMQ_QUEUE"]

        channel.queue_declare(queue=queue,durable=True)
        channel.basic_publish(exchange='', 
            routing_key=queue,
            properties=pika.BasicProperties(
                headers={"model":model},
                content_type="application/json",
            ),
            body=payload)
        return True
