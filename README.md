# agent7

![Alt text](photos/a7_1.PNG?raw=true "Sch Tasks")

## What is it?
Agent7 is a security monitoring agent for Windows endpoints (Windows 7,8,10, Server 08,12,16 +). At a high level, the agent runs as a local service on the endpoint and sends data to the server for more analysis. It also have a remote interactive module and a Active Directory module.

## Why Agent7?
There is no shortage of tools to collect data from endpoints and send it to a central server. Similar tools that come to mind are OSquery, OSSEC (Wazuh included), Sysmon, etc. While these tools are great, you will spend hundreds of hours trying to get actionable data from them because they lack a decent server component. However with Agent7, you can immediately receive actionable information (such as insecure file permissions and overprivileged users). While there are built in alerts and dashboards, there is also a full API that you can query for your own alerts and integrations.

## How does it work?
There is a agent and server component. You install the `.exe` on the endpoints and it communicates with the server. 90% of the data is collected via the Windows API but there are a few methods that use WMI. 

## What are the key features?
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

You can also tell agents to collect data from Active Directory. Such as:  
+ Users, Groups & Computers (along with their attributes)    
+ GPO  
+ SysVol & permissions  
+ Domains & Domain Controllers  

## How to Install
+ Clone the Repo  
+ Build it with `docker build -t agent7_1.0 .`  
+ Start it with `docker run -p 5000:5000/tcp agent7_1.0:latest`  
+ Browse to port 5000 where the email is `admin@example.com` and password is `Password1`
