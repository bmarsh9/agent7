# Agent7 - Security Agent

## Table of Contents
1. [What is it?](#what-is-it)
2. [Why Agent7?](#why-agent7)
3. [How does it work?](#how-does-it-work)
4. [What data does it collect & track](#What-data-does-it-collect--track)
5. [How to Install](#how-to-install)
6. [What is next on the roadmap?](#what-is-next-on-the-roadmap)
7. [Architecture](#Architecture)
8. [Considerations](#considerations)

### What is it?
Agent7 is a security monitoring agent for Windows endpoints (Windows 7,8,10, Server 08,12,16 +). At a high level, the agent runs as a local service on the endpoint and sends data to the server for more analysis. It also has a remote interactive/shell module and a Active Directory module.  

![Alt text](photos/a7_dash.PNG?raw=true "Dashboard")  

### Why Agent7?
There is no shortage of tools to collect data from endpoints and send it to a central server. Similar tools that come to mind are OSquery, OSSEC (Wazuh included), Sysmon, etc. While these tools are great, you will spend hundreds of hours trying to get actionable data from them because they lack a decent server component. However with Agent7, you can immediately receive actionable information (such as insecure file permissions and overprivileged users). While there are built in alerts and dashboards, there is also a full API that you can query for your own alerts and integrations.

### How does it work?
There is a agent and server component. You install the `.exe` on the endpoints and it communicates with the server. 90% of the data is collected via the Windows API but there are a few methods that use WMI. There are a couple main features:  
+ Collect data from the endpoint on a periodic basis
+ Collect data from Active Directory  
+ Agent Interact - Allows the user to remote in or shell into a host and run commands. You can also run commands on a group of hosts.  
+ Insights - Automatic queries that run on the collected data and finds misconfigurations or similar
+ Privileged User/Group identification

![Alt text](photos/a7_map.PNG?raw=true "Logon Map")  

### What data does it collect & track?
The list below is not exhaustive but gives a good overview.   
+ Scheduled tasks  
+ Software  
+ Updates  
+ Logged on users  
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

![Alt text](photos/a7_1.PNG?raw=true "Sch Tasks")  

### How to Install  
##### Set up the Server
+ Clone the Repo  
+ Build it with `docker build -t agent7_1.0 .`  
+ Start it with `docker run -p 5000:5000/tcp agent7_1.0:latest`  
+ Browse to port 5000 where the email is `admin@example.com` and password is `Password1`  
##### Set up the Agent  
+ Download the `agent7_installer.exe` onto the Windows workstation/server  
+ Open up cmd or powershell and run `.\agent7_installer.exe /verysilent /server=<ip of server> /key=<sitekey> /group=mycustomgroup`. The default `Site Key` is `737e079a-6170-4aae-91a6-60aca1f213aa`.  
+ Open Event Viewer > Windows Logs > Application and look for EventID `2002` (`Initialization Successful`) from Agent7. This means that the agent installed correctly. Then look for EventID `2003`. `Agent Registered` means the agent successfully registered with the server.
+ Verify that the agent checked into the server as well
##### Uninstall  
+ Right-click and uninstall from Control Panel

### What is next on the roadmap?  
+ Documentation (lots of that)  
+ Make it easier to write custom Insights  
+ Explore possibility of a Linux based agent as well  
+ Distributed network scanner with the agents  
+ Separate components into single containers (nginx,app,postgres,redis,rabbit) and provide Helm charts for Kubernetes  
+ Use JWT for authn/authz. Currently the agent uses the shared Site Key to register. Upon registration, the server creates a unique token for the agent. The agent saves the token and uses it for authentication. B/c the token is shared on the server side, it must perform a database lookup everytime an agent sends data. JWT would be much quicker and you could separate out the control and data plane (which many tools do today) thanks to public keys. Currently, the agent token can only POST data.. so a user could not use it to query the server API.

### Architecture
![Alt text](photos/agent7_arch.PNG?raw=true "Architecture")  

### Considerations 
+ You will need to run the RMQ Connector if you are using more than 2-3 agents to handle the load.  
+ The default `Site Key` is `737e079a-6170-4aae-91a6-60aca1f213aa`. Please change this in the `app/local_settings.py` file.  
+ By default, the agent does NOT verify the server certificate before sending the data via TLS.
+ By default, Nginx (which fronts the app) uses a preconfigured private/public key for TLS.  
+ Data is not currently compressed before being sent from agent -> server (though this is a new feature being added)  
+ RabbitMQ default user/pass is Admin:Admin and only listens on localhost. Traffic is unencrypted.  
+ Postgresql creds are default as well (db1:db1) and these should be set to something stronger.

### Building  
##### Docker  
1.) Tag image: `docker tag agent7_ui bmarsh13/public-dev:agent7_ui`  
2.) Public image: `docker push bmarsh13/public-dev:agent7_ui`
