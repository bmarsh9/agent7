# RMQ Connector

### What is it?  
+ Dedups events from agents sitting in the Queues and inserts the data into the database 
+ It must have network access & valid creds to the RabbitMQ server AND the Postgresql database (if these components are on different hosts, you should set up TLS encryption for the connections - default is unencrypted)

### Install  
+ Run `pip3 install -r requirements.txt`  
+ Run `apt-get install sqlite3`  
+ Start the connector -> `python3 connector.py`

### How do I know its working?  
+ If you get no errors upon start up  
+ You see data being populated in the Agent7 UI  
+ Screenshot looks something like this below  

![Alt text](../photos/rmq_connector_start.PNG?raw=true "RMQ Connector Output")  
