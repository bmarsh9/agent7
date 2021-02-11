# Agent7 - Security Agent <img alt="Flask" src="https://img.shields.io/badge/flask%20-%23000.svg?&style=for-the-badge&logo=flask&logoColor=white"/> <img alt="Postgres" src ="https://img.shields.io/badge/postgres-%23316192.svg?&style=for-the-badge&logo=postgresql&logoColor=white"/> <img alt="Python" src="https://img.shields.io/badge/python%20-%2314354C.svg?&style=for-the-badge&logo=python&logoColor=white"/> <img alt="jQuery" src="https://img.shields.io/badge/jquery%20-%230769AD.svg?&style=for-the-badge&logo=jquery&logoColor=white"/>  


<p align="center">
  <img height="150px" src="https://github.com/bmarsh9/agent7/raw/main/photos/a7_logo.PNG?raw=true" alt="Logo"/>
</p>

| :zap:        Agent7 now ships with a White and Dark Theme!   |
|-----------------------------------------|

Dark Theme            |  White Theme (:zap: BETA)
:-------------------------:|:-------------------------:
![](photos/a7_dash.PNG?raw=true)  |  ![](photos/a7_white.PNG?raw=true)

## Table of Contents
1. [What is it?](#what-is-it)
2. [Why Agent7?](#why-agent7)
3. [How does it work?](#how-does-it-work)
4. [What data does it collect & track](#What-data-does-it-collect--track)
5. [How to Install](#how-to-install)
6. [Powerful API for Custom Queries](#api-examples)
7. [What is next on the roadmap?](#what-is-next-on-the-roadmap)
8. [Architecture](#Architecture)
9. [Considerations](#considerations)  
10. [Debugging](#debugging)  


### What is it?
Agent7 is a security monitoring agent for Windows endpoints (Windows 7,8,10, Server 08,12,16 +). At a high level, the agent runs as a local service on the endpoint and sends data to the server for more analysis. It also has a remote interactive/shell module and a Active Directory module. The server component consists of 5 docker containers (3 custom containers and postgresql/rabbitmq). The [API](#api-examples) is also a great way to gain insights into your fleet.

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
+ Clone the Repo (or just copy down the `docker-compose.yml` file)  
+ Run `docker-compose up -d postgres_db rabbitmq && docker-compose up -d`  (Pro Tip, edit the `THEME_COLOR` env variable in the `docker-compose` file to set a `dark` or `white` theme. I prefer the dark theme  
+ Browse to your server URL. The email is `admin@example.com` and password is `Password1` (The UI takes a few minutes to come online so you may get a few 500 errors)  

##### Set up the Agent  
+ Download the `agent7_installer.exe` from this repo (`./windows_agent/agent7_installer.exe`) onto the Windows workstation/server  
+ Open up cmd or powershell and run `.\agent7_installer.exe /verysilent /server=<ip of server> /verifytls=no`  (WARNING: Do not set `/verifytls=no` outside of testing. This disables server certificate validation!!)    
+ Open Event Viewer > Windows Logs > Application and look for EventID `2002` (`Initialization Successful`) from Agent7. This means that the agent installed correctly. Then look for EventID `2003`. `Agent Registered` means the agent successfully registered with the server.
+ Verify that the agent checked into the server as well  

##### Uninstall  
+ Right-click and uninstall from Control Panel or uninstall via the console UI

### API Examples  
The API has fantastic support for any advanced queries or custom analytics you want to gather from your agent fleet. For example, if we want to view `All Software that was installed in the last 5 days`...  

![Alt text](photos/a7_api.PNG?raw=true "API")  

Or if you wanted to view all privileged users that logged in within the last week  

![Alt text](photos/a7_api_2.PNG?raw=true "API")  

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
+ The default `Site Key` is `737e079a-6170-4aae-91a6-60aca1f213aa`. Please change this in the `app/local_settings.py` file and via the command line when installing the agent.  
+ By default, Nginx (which fronts the app) uses a preconfigured private/public key for TLS. Change this for prod    
+ Data is not currently compressed before being sent from agent -> server (though this is a new feature being added)  
+ Components (Postgres,RabbitMQ) all use default/weaks creds and the traffic is unencrypted. Docker-compose places them on their own network so they can't be reached but it is still best practice to set non-default and strong secrets  
+ If installing on lots of hosts (+100), you may want to adjust and lengthen the checkin time of the agents. By default, they check in every 20 seconds. This can be seen here:
https://github.com/bmarsh9/agent7/blob/main/windows_agent/build_docs/agent7.py#L71  
+ Restarting Postgres or Agent7_ui will delete all data. Consider placing placing Postgres on a volume for data persistence  

### Debugging  
Check the containers by running `docker ps`. It should look something like below:  
![Alt text](photos/a7_docker_status.PNG?raw=true "Docker ps")  

After that, start running `docker logs <container_name> -f` and looking for errors. File a bug if you need help.  

If you see the error `Missing table model: <>. Please add it to the RDS Mapper` while running `docker logs agent7_connector -f`... then you can try to restart that container with `docker-compose restart rmq_connector` and see if that fixes the issue.  


### Building  
##### Docker  
1.) Tag image: `docker tag agent7_ui bmarsh13/public-dev:agent7_ui`  
2.) Public image: `docker push bmarsh13/public-dev:agent7_ui`  

##### Clean dataset:  
`docker-compose stop rmq_connector && docker-compose rm rmq_connector && docker-compose up -d`

