# agent7

### What is it?
Agent7 is a security monitoring agent for Windows endpoints (Windows 7,8,10, Server 08,12,16 +). At a high level, the agent runs as a local service on the endpoint and sends data to the server

### What are the key features?
The list below is not exhaustive but gives a good overview.   
+ Allows the user to interact with the agents from the server console. Basically you access a shell on the endpoint and can run queries or collect data in real-time  
+ Collects data on scheduled tasks  
+ Software  
+ Updates  
+ Network Connections  
+ Network Shares  
+ Services  
+ Processes  
+ Local Users  
+ Local Groups  
+ System Metrics  
+ Start up tasks  
+ Memory and Disk space  
+ Printers  
+ Network Pipes  
+ Network Sessions  
+ Registry Keys  



### Build
docker build -t agent7_1.0 .

### Run
docker run -p 5000:5000/tcp agent7_1.0:latest

#### Browse to port 5000
##### Email: admin@example.com
##### Password: Password1 
