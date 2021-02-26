import win32serviceutil
import win32service
import win32event
import win32security
import win32ts
import win32print
import win32api
import win32netcon
import win32con
import ntsecuritycon
import win32net
import win32com.client
import servicemanager
from winreg import HKEY_LOCAL_MACHINE,HKEY_USERS,OpenKey,EnumKey,EnumValue,KEY_READ,HKEY_CURRENT_USER,KEY_WOW64_32KEY,KEY_WOW64_64KEY,QueryInfoKey,QueryValueEx,ConnectRegistry
import win32evtlog
import win32evtlogutil
import json,requests,argparse,zipfile
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM
import platform,socket,sys,os,subprocess,re
import pythoncom
import threading
from datetime import datetime,timedelta
import time
import psutil
from psutil._common import bytes2human
import hashlib
from tabulate import tabulate
tabulate.PRESERVE_WHITESPACE = True
import operator,ast
import active_directory
import struct
import pywintypes
import xmltodict
import random
from ldap3.utils.dn import to_dn
from requests.adapters import HTTPAdapter

svc_name="agent7"

class AppServerSvc(win32serviceutil.ServiceFramework):
    _svc_name_ = svc_name   
    _svc_display_name_ = svc_name
    _svc_description_ = "Collection Tool"

    def __init__(self,args):
        win32serviceutil.ServiceFramework.__init__(self,args)
        self.hWaitStop = win32event.CreateEvent(None,0,0,None)
        socket.setdefaulttimeout(60)

    def SvcStop(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,0x7d1,
                              ('[INFO] Attempting to Stop the Service.',''))    
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)      

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,0x833,
                              ('[INFO] Attempting to Start the Service',''))                              
        self.ProgramManager(self.hWaitStop).begin()
        
    class ProgramManager():       
        def __init__(self,hWaitStop):
            pythoncom.CoInitialize()
            import wmi        
            self.c = wmi.WMI(None,find_classes=False)
            self.hWaitStop = hWaitStop
            self.rc = None
            self.safe_ini=True
            self.svc_start = datetime.utcnow()
            self.errors = 0
            self.wait_time = 20000
            
            #//Get Registry Keys
            self.obj = Registry_Read("hklm")            
            self.home_reg_path = os.path.join("System\\CurrentControlSet\\Services",svc_name)            
            reg = self.obj.get_values(self.home_reg_path)
            self.version = reg["version"]
            installdir = reg.get("installdir")
            if not installdir:                                    
                self.working_dir = os.path.join(os.path.abspath(os.sep),"program files",svc_name)
                self.temp_dir = os.path.join(os.path.abspath(os.sep),"program files",svc_name,"temp")
                self.log_dir = os.path.join(os.path.abspath(os.sep),"program files",svc_name,"logs")
                self.log_file = os.path.join(self.log_dir,"debug.log")
            else:
                self.working_dir = installdir
                self.temp_dir = os.path.join(installdir,"temp")
                self.log_dir = os.path.join(installdir,"logs")   
                self.log_file = os.path.join(self.log_dir,"debug.log")                
            
            try:
                self.create_folders(subfolders=["logs","data","temp"])
                self.cmdserver = reg["server"]
                self.cmdurl = "https://{}/api/agent".format(self.cmdserver)
                self.site_key = reg["key"]                
                self.aid = reg["aid"]
                self.group = reg.get("group","default_group")
                vtls = reg.get("verifytls","yes")
                if vtls == "no":
                    self.verifytls = False
                else:
                    self.verifytls = True
                self.headers = {
                    "user-agent": "Agent7",
                    "site-key":self.site_key,
                    "aid":self.aid,
                }
                self.registered = 0                
                
            except Exception as e:
                self.safe_ini=False
                self.event_logger(message="Error reading init configuration settings. Error: {}".format(str(e)),log_type="error", eventid=4001)
                
            try:
                # get general info that is used everywhere in the program
                self.hostname = win32api.GetComputerName()
                self.fqdn = win32api.GetComputerNameEx(win32con.ComputerNameDnsFullyQualified) #socket.getfqdn()
                self.domain_joined = is_domain_joined()
                self.is_dc = is_dc()
                
                #self.domain = win32net.NetWkstaGetInfo(None,100).get("langroup")
                domain_info = get_domain_info()
                self.domain = domain_info.get("domain")                
                self.dc = domain_info.get("domaincontrollername")
                self.dc_ip = domain_info.get("domaincontrolleraddress")
                self.forest = domain_info.get("forest")                                                     
                    
                # get build info
                path_1=r'software\\microsoft\\windows nt\\currentversion'
                reg_build = self.obj.list_contents(path_1) # lowercase the keys                                               
                if not reg_build:
                    reg_build = {}                    
                    
                # get OU and site    
                path_2 = r'software\\microsoft\\windows\\currentversion\\group policy\\state\\machine' # OU and Site
                reg_dn = self.obj.list_contents(path_2) # lowercase the keys
                if not reg_dn:
                    reg_dn = {}                
                                        
                self.sys_data = {
                    #// Generate system data          
                    "fqdn": self.fqdn,
                    "hostname": self.hostname,
                    "domain": self.domain,
                    "forest":self.forest,
                    "dn":reg_dn.get("Distinguished-Name"),
                    "site":reg_dn.get("Site-Name"),
                    "domain_joined": self.domain_joined,
                    "is_dc": self.is_dc,
                    "family": platform.system(),
                    "release": platform.release(),
                    "sysversion": platform.version(),
                    "installtype": reg_build.get("InstallationType"),
                    "edition": reg_build.get("ProductName"),
                    "build": reg_build.get("CurrentBuild"),
                    "machine":platform.machine(),
                    "processor":platform.processor(),
                    "cpu": psutil.cpu_count(),
                    "adcollector":0,
                    "advaulter":0,
                    "rtr":0
                }              
            except Exception as e: # error occurred but we dont want to exit
                #self.safe_ini=False
                self.sys_data = {}
                self.event_logger(message="(Proceeding) Error collecting init platform settings. Error: {}".format(str(e)),log_type="error", eventid=4002)
                
            if self.safe_ini is True:
                self.event_logger(message="Initialization successful.",log_type="info", eventid=2002)               
                       
        def begin(self):
            #// Enter Program Loop
            while self.rc != win32event.WAIT_OBJECT_0 and self.safe_ini is True:
                try:
                    self.checkStop(wait_time=self.wait_time) 
                    if not self.registered:
                        self.register_agent() #// Register the agent with the server                           
                        
                    #self.get_health() #// Post agent health and details
                    self.get_job() #// Get job details       
                    
                    if self.sys_data.get("rtr"):
                        self.interact() #// Run shell cmd                    
                except self.CustomCode:                
                    self.event_logger(message="Received stop code. Stopping service.")  
                    break 
                except requests.exceptions.ConnectionError as e:  
                    self.event_logger(message="Unable to contact server: {}".format(self.cmdurl)) 
                #except Exception as e:
                #    self.errors += 1
                #    self.event_logger(message="Catchall error: {}".format(str(e)))  
                    
        def checkStop(self,wait_time=3000):
            '''
            :Description - Wait function, also checks if stop is requested
            '''
            self.rc = win32event.WaitForSingleObject(self.hWaitStop,wait_time)
            if self.rc == win32event.WAIT_OBJECT_0: # stop requested
                raise self.CustomCode(1000)
            return True                                            
            
        # def get_health(self):
            # payload = {
                # "status": "ok",
                # "errors": self.errors,
                # "version": self.version,
                # "svc_start": self.svc_start.strftime("%Y/%m/%d %H:%M:%S"),
                # "svc_uptime": (datetime.utcnow() - self.svc_start).total_seconds()
            # }
            # response = self.post_data("health", payload=payload, retries=1)            
            # if not response:
                # return False
                
            # self.sys_data["adcollector"] = int(response.get("adcollector",0)) ## collect data from AD
            # self.sys_data["advaulter"] = int(response.get("advaulter",0)) ## manage domain accounts
            # self.sys_data["rtr"] = int(response.get("rtr",0)) ## if rtr is enabled
            
            # if int(response.get("update",0)):
                # self.update()                        
            # elif int(response.get("uninstall",0)):
                # self.uninstall()
            # return True

        def registered_task(self,func=None,console=None,vertical=None,inc=[],exc=[],**kwargs):        
            job_map = [  
                {"name":"get-hash","func":self.get_hash,"desc":"Hash as file.","params":"file","example":"job=get-hash,file=C:\\users\\myfile.txt"},
                {"name":"get-pid","func":self.get_pid,"desc":"Get PIDs (process IDs) for a process name.","params":"pname","example":"job=get-pid,pname=svchost"},
                {"name":"get-software","func":self.get_software,"desc":"Get software installed in the registry.","params":"n/a","example":"job=get-software"},
                {"name":"get-connection","func":self.get_netconnection,"desc":"Get current network connections.","params":"n/a","example":"job=get-connection"},
                {"name":"get-netsession","func":self.get_netsession,"desc":"Get remote host and username connected to host.","params":"sess_id","example":"job=get-netsession"},                
                {"name":"get-platform","func":self.get_platform,"desc":"Get system platform data.","params":"n/a","example":"job=get-platform"},
                {"name":"get-regkey", "func":self.get_regkey, "desc":"Get registry key values.","params":"hive,keypath,inc,exc","example":"job=get-regkey,keypath=System\CurrentControlSet\Services"},
                {"name":"get-memory","func":self.get_memory,"desc":"Get current memory.","params":"n/a","example":"job=get-memory"},
                {"name":"get-disk","func":self.get_disk,"desc":"Get current disk usage.","params":"n/a","example":"job=get-disk"},
                {"name":"get-printer","func":self.get_printer,"desc":"Get local and recent printer connections.","params":"n/a","example":"job=get-printer"},                
                {"name":"get-event","func":self.get_event,"desc":"Get events in the Windows Event viewer.","params":"logtype,eventid,hours,limit,start,end","example":"job=get-event,logtype=Security,eventid=4624,start=06/10/19 13:45:50"},
                {"name":"get-schtask","func":self.get_schtask,"desc":"Get scheduled tasks.","params":"n/a","example":"job=get-schtask"},
                {"name":"get-service","func":self.get_service,"desc":"Get current services in SCM.","params":"filter,exc,inc","example":"job=get-service,inc=field1;field2,exc=field3"},
                {"name":"get-process","func":self.get_process,"desc":"Get current processes.","params":"filter,exc,inc","example":"job=get-process"},                
                {"name":"get-updates","func":self.get_updates,"desc":"Get all windows updates.","params":"filter,exc,inc","example":"job=get-updates"},
                {"name":"get-patch","func":self.get_patch,"desc":"Get hotfixes on the host.","params":"filter,exc,inc","example":"job=get-patch"},
                {"name":"get-user","func":self.get_user,"desc":"Get local user accounts.","params":"override,filter,exc,inc","example":"job=get-user"},
                {"name":"get-group","func":self.get_group,"desc":"Get local group accounts.","params":"override,filter,exc,inc","example":"job=get-group"},
                {"name":"get-system","func":self.get_system,"desc":"Get verbose system information.","params":"filter,exc,inc","example":"job=get-system"},
                {"name":"get-logon","func":self.get_logon,"desc":"Get logon and session data.","params":"filter,exc,inc","example":"job=get-logon"},
                {"name":"get-share","func":self.get_share,"desc":"Get network shares.","params":"filter,exc,inc","example":"job=get-share"},
                {"name":"get-netadapter","func":self.get_netadapter,"desc":"Get network adapter data.","params":"filter,exc,inc","example":"job=get-netadapter"},
                {"name":"get-startup","func":self.get_startup,"desc":"Get startup commands.","params":"filter,exc,inc","example":"job=get-startup"},
                {"name":"get-pipe","func":self.get_pipe,"desc":"Enumerate named pipes.","params":"filter,exc,inc","example":"job=get-pipe"},
                {"name":"get-neighbor","func":self.get_neighbor,"desc":"Enumerate local neighbors","params":"filter,exc,inc","example":"job=get-neighbor"},
                {"name":"get-scan","func":self.get_scan,"desc":"Scan local neighbors","params":"filter,exc,inc","example":"job=get-scan"},                  
                {"name":"raw","func":"n/a","desc":"Execute raw shell commands.","params":"cmd","example":"job=raw,cmd=tasklist /svc"},
                {"name":"get-help","func":"n/a","desc":"Display the Help menu.","params":"none","example":"job=get-help"},
                {"name":"dir or ls","func":"n/a","desc":"List directory contents.","params":"path","example":"job=ls OR job=ls,path=C:\\users"},
                {"name":"cd","func":"n/a","desc":"Change directories.","params":"path","example":"job=cd,path=C:\\users"},
                {"name":"valid-raw","func":"n/a","desc":"View valid shell commands (loaded from server).","params":"none","example":"job=valid-raw"},
                {"name":"resolve-ip","func":"n/a","desc":"resolve IP address to a hostname.","params":"ip","example":"job=resolve-ip;ip=10.100.1.10"},                                
                {"name":"get-ad-groupmember","func":self.get_ad_groupmember,"desc":"Get group members of a AD group.","params":"path","example":"job=cd,path=C:\\users"},
                {"name":"get-ad-memberof","func":self.get_ad_memberof,"desc":"Get assets of a group.","params":"path","example":"job=cd,path=C:\\users"},
                {"name":"get-ad-group","func":self.get_ad_group,"desc":"Get AD groups.","params":"path","example":"job=cd,path=C:\\users"},
                {"name":"get-ad-user","func":self.get_ad_user,"desc":"Get AD users.","params":"path","example":"job=cd,path=C:\\users"},
                {"name":"get-ad-computer","func":self.get_ad_computer,"desc":"Get AD computers.","params":"path","example":"job=cd,path=C:\\users"},
                {"name":"get-ad-ou","func":self.get_ad_ou,"desc":"Get AD organizational unit.","params":"path","example":"job=cd,path=C:\\users"},
                {"name":"get-ad-gpo","func":self.get_ad_gpo,"desc":"Get AD GPOs.","params":"path","example":"job=cd,path=C:\\users"},
                {"name":"get-ad-dc","func":self.get_ad_dc,"desc":"Get AD domain controllers.","params":"path","example":"job=cd,path=C:\\users"},
                {"name":"get-ad-sysvol","func":self.get_ad_sysvol,"desc":"Collect files and ACLs in Sysvol","params":"path","example":"job=cd,path=C:\\users"},
                {"name":"get-ad-domain","func":self.get_ad_domain,"desc":"Get current domain.","params":"path","example":"job=cd,path=C:\\users"},
                {"name":"get-auditkeys","func":self.get_auditkeys,"desc":"Get Registry AuditKeys.","params":"none","example":"job=get-auditkeys"},
                {"name":"set-localaccount","func":self.manage_local_account_password,"desc":"Set password for local account.","params":"none","example":"job=get-auditkeys"},
                {"name":"set-adaccount","func":self.manage_ad_account_password,"desc":"Set password for AD account.","params":"none","example":"job=get-auditkeys"}               
            ]  
            
            if console:
                for job in job_map:
                    job.pop("func",None)                                           
                filtered_data = self.filter_fields(job_map,inc=inc,exc=exc)            
                return self.to_tabulate(filtered_data,vertical=vertical)             
            for job in job_map:
                if job.get("name") == func:
                    return job.get("func")
            return None             
            
        def register_agent(self,force=0): 
            attempts = 0
            while not self.registered or force:
                if attempts < 5:
                    self.checkStop(wait_time=5000)
                    payload = self.get_platform(force=1)[0]
                    response = self.post_data("register", payload=payload)
                    
                    if response:                               
                        if response.get("registered"):
                            self.event_logger(message="Agent Registered",eventid=2003)
                            self.registered = 1
                            self.headers["token"] = response.get("token")
                            return True
                    self.event_logger(message="Unable to register the agent. Trying again {}/5.".format(attempts),log_type="warning", eventid=3001)                        
                    attempts += 1
                else:
                    self.event_logger(message="Retries expired for registering agent.",log_type="warning", eventid=3002)                                        
                    # break and stop service
                    raise self.CustomCode(1000)
            return None

        #-----------------------------------------------Net Connection Functions-----------------------------------------------        
        def get_job(self):
            '''
            .Description: Grabs the job from the server and sends it to route_plugins function for routing
            '''
            payload = {
                "status": "ok",
                "errors": self.errors,
                "version": self.version,
                "svc_start": self.svc_start.strftime("%Y/%m/%d %H:%M:%S"),
                "svc_uptime": (datetime.utcnow() - self.svc_start).total_seconds()
            }
            response = self.post_data("job", payload=payload, retries=1)            
            
            if response:
                self.sys_data["adcollector"] = int(response.get("adcollector",0)) # collect data from AD
                self.sys_data["advaulter"] = int(response.get("advaulter",0)) # manage domain accounts
                self.sys_data["rtr"] = int(response.get("rtr",0)) # if rtr is enabled   
                if int(response.get("update",0)):
                    self.update()                        
                elif int(response.get("uninstall",0)):
                    self.uninstall()                              
                
                jobset = response.get("jobset",None)
                if jobset:                
                    # open requests session
                    session = self.requests_session()
                    with session:
                        for task in jobset: 
                            if task.get("enabled"):
                                self.checkStop(wait_time=100)
                                name = task.get("task")
                                params = {
                                    "interval":task.get("interval"),
                                    "force":task.get("force"),
                                    "filter":task.get("filter",{}),
                                    "inc":task.get("inc",[]),
                                    "exc":task.get("exc",[])
                                }
                                func = self.registered_task(func=name)
                                if func:
                                    results = func(**params)
                                    if results:
                                        if isinstance(results,dict):
                                            results = [results]
                                            
                                        payload = {"task":name,"dataset":results}  
                                        endpoint = os.path.join("collection",name)
                                        self.post_data(endpoint, session=session, payload=payload)
                                    #// No results
                else:
                    # invalid or empty job
                    pass
            return None
       
        def requests_session(self,session=None):
            session = session or requests.Session()            
            adapter = HTTPAdapter()
            #session.mount('http://',adapter)
            session.mount('https://',adapter)
            return session
            
        def post_data(self, endpoint, payload={}, session=None, retries=3, backoff=30000):
            '''
            .description: Posts data back to the server
            '''
            if not isinstance(payload,dict):
                payload = {"message":str(payload)}
            if not session:
                session = self.requests_session()
                
            url = (os.path.join(self.cmdurl,endpoint,self.aid).replace(os.sep,"/"))                
            for attempt in range(0,retries):                            
                try:
                    response = session.post(
                        url,
                        json=payload,
                        headers=self.headers,
                        verify=self.verifytls,
                        stream=False,
                        timeout=20
                    )
                except Exception as e:
                    self.event_logger(message="Caught exception during post_data: {}".format(str(e)))
                else:
                    status_code = response.status_code
                    if response.ok:
                        return response.json()
                    else: # handle other status codes
                        if status_code == 401:
                            self.registered = 0
                            self.register_agent(force=1)                        
                self.checkStop(wait_time=backoff)
            return None
            
        def get_data(self, endpoint, retries=3, backoff=30000):        
            '''
            .description: Get data from the server
            '''          
            url = (os.path.join(self.cmdurl,endpoint,self.aid).replace(os.sep,"/"))
            #// Attempt 3 times to contact server
            for attempt in range(0,retries):
                try:
                    response = requests.get(
                        url,
                        headers=self.headers,
                        verify=self.verifytls,
                        stream=False,
                        timeout=20
                    )
                except Exception as e:
                    self.event_logger(message="Caught exception during get_data: {}".format(str(e)))
                else:
                    status_code = response.status_code
                    if response.ok:
                        return response.json()
                    else: # handle other status codes
                        if status_code == 401:
                            self.registered = 0
                            self.register_agent(force=1)                        
                self.checkStop(wait_time=backoff)
            return None                     

        def get_file(self, save_folder, filename,url=None,retries=3,endpoint="file",writemethod="wb",overwrite=True,backoff=30000):
            '''
            .description: Downloads file from the server
            .save_folder: Where to save the file once downloaded
            .filename: Filename to search for on the server
            '''
            if not url:
                url = (os.path.join(self.cmdurl,endpoint,self.aid).replace(os.sep,"/"))          
            chunk_size = 2000
            abs_filepath = os.path.join(save_folder,filename)            
            file = requests.get(url,headers=self.headers,stream=True,verify=self.verifytls)
            for attempt in range(0,retries):            
                if file.ok:
                    if os.path.exists(abs_filepath) and overwrite is True:
                        os.remove(abs_filepath)
                    #// Combine the save folder and the filename downloaded from the server
                    with open(abs_filepath,writemethod) as fd:
                        for chunk in file.iter_content(chunk_size):
                            fd.write(chunk)
                    if os.path.exists(abs_filepath):
                        return abs_filepath
                else:
                    self.event_logger(message="Unable to download file from server. Status code:{}. Response:{}".format(file.status_code,r.text))                      
                self.checkStop(wait_time=backoff)
            return None         
        #-----------------------------------------------Uninstall Function-----------------------------------------------        
        def uninstall(self):
            '''
            .description: Uninstall the agent            
            '''
            uninstall_exe = self.locate_file(self.working_dir,"unins","exe")
            if uninstall_exe:
                self.event_logger(message="Uninstalling the program.",log_type="info")
                subprocess.Popen(                            
                    [uninstall_exe,"/VERYSILENT","/SUPPRESSMSGBOXES"],
                    close_fds=True,
                    creationflags=0x00000008
                )
                return True
            self.event_logger(message="Unable to locate the uninstall file.")                
            return None
            
        #-----------------------------------------------Update Function-----------------------------------------------                                         
        def update(self):
            '''
            .description: Update the exe
            '''
            save_file = "agent7.exe"
            response = self.get_data("version",retries=1)
            if response:
                server_version = response.get("version",None)
                #cmd_server = response.get("cmd_server",None) #if want server to change settings
                #site_key = response.get("site_key",None)
                cmd_server="/server={}".format(self.cmdserver)
                site_key="/key={}".format(self.site_key)
                install_group="/group={}".format(self.group)
                if server_version is None:
                    raise Exception("Unable to update. Invalid version from server:{}".format(server_version))
                if server_version > self.version:
                    self.event_logger(message="Detected a new version on the server. Performing an update.")  
                    if self.get_file(self.temp_dir,save_file,endpoint="update"):
                        self.event_logger(message="Successfully downloaded the new executable. Updating.")

                        subprocess.Popen(                            
                            [os.path.join(self.temp_dir,save_file),"/VERYSILENT","/SUPPRESSMSGBOXES",cmd_server,site_key,install_group],
                            close_fds=True,
                            creationflags=0x00000008
                        )

                        raise self.CustomCode(1000)
                        #win32serviceutil.StopService(svc_name)
                    else:
                        self.event_logger(message="Unable to download the updated program.", log_type="error")      
                else:
                    self.event_logger(message="Server version is older. Skipping update.")  
            else:
                raise Exception("Unable to update. Response from server was not OK.")                             

        #-----------------------------------------------Wrapper Scheduler for all Tasks-----------------------------------------------
        def should_we_run(func): 
            '''
            :Description - Wrapper function for tasks to execute on diff time intervals
                1. Runs task and creates attr in registry with last run time
                2. If task received <interval> is > last run, run task
                3. If task received <interval> is < last run, dont run task                    
            '''
            def inner(*args, **kwargs):
                obj = Registry_Read("hklm")            
                reg_path = os.path.join("System\\CurrentControlSet\\Services",svc_name) 
                
                attr_name = func.__name__
                force = kwargs.get("force",0)
                console = kwargs.get("console",0)
                interval = kwargs.get("interval",60)                                                               
                
                reg = obj.get_values(reg_path)
                lastrun = reg.get(attr_name)
            
                if not lastrun: #// if function has not been run before, run now
                    lastrun = interval+1
                                    
                elapsed = time.time() - float(lastrun)
                if elapsed < interval and not force and not console:
                    #// Not enough time has elapsed since the last run  
                    return None
                    
                #// Run function, update last run time if not console
                if not console and not force:
                    obj.createRegistryParameter(reg_path,attr_name,time.time())
                return func(*args, **kwargs)           
            return inner                                    

        #-----------------------------------------------Feature Functions----------------------------------------------- 
        class Command():
            def __init__(self, cmd):
                self.cmd = cmd
                self.process = None
                self.output = None

            def run(self,timeout):
                def target():
                    devnull = open(os.devnull,'wb')                              
                    self.process = subprocess.Popen(self.cmd, shell=False, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE,stdin=devnull)
                    bytes = self.process.stdout.read() + self.process.stderr.read()
                    self.output = bytes.decode("utf-8", errors="replace")
                    self.process.communicate()                   
                thread = threading.Thread(target=target)
                thread.start()

                thread.join(timeout)
                if thread.is_alive():
                    self.process.terminate()
                    thread.join()
                #rtncode = self.process.returncode            
                return str(self.output)  
                
        def interact(self):      
            response = None
            valid_cmd = []         
            output = None
            #// Get valid commands
            get_cmd = self.get_data("valid-cmd/rtr")
            if get_cmd:
                new_cmd = get_cmd.get("commands")
                if isinstance(new_cmd,list):
                    valid_cmd = list(set(new_cmd+valid_cmd))                       
            try:
                response = self.get_data("interactive",retries=1, backoff=5000)
                if response:
                    response = response.get("response",None)
                    cmdline = response.get("cmd",None)
                    if bool(cmdline and cmdline.strip()):
                        args_dict = self.parse_args(cmdline.strip())
                        
                        if args_dict:
                            job = args_dict.get("job")
                            args_dict["console"] = 1
                            args_dict.pop("job",None) #// remove to prevent future conflicts                            
                            if job == "get-help":
                                output = self.registered_task(**args_dict)  
                            elif job == "resolve-ip":
                                ip = args_dict.get("ip")
                                output = self.resolve_ip(ip)
                            elif job == "valid-raw":
                                output = valid_cmd                                                                                                                                                  
                            elif job in ('dir','ls'):
                                directory = args_dict.get("path",os.getcwd())
                                path = directory.replace(os.sep,"/")                                               
                                output = self.get_dir(path)
                            elif job == 'cd':
                                directory = args_dict.get("path")                            
                                try:
                                    os.chdir(directory.strip())
                                    output = "Changed directories to: %s" % str(os.getcwd())
                                except Exception as e:
                                    output = "Could not change directory: %s" %str(e)
                            elif job == "raw":
                                cmdline = args_dict.get("cmd")                              
                                cmdline = cmdline.split(" ")
                                if cmdline[0] not in valid_cmd:                        
                                    raise Exception("Command is not in valid commands!")                                  
                                try:                                
                                    output = self.Command(cmdline).run(timeout=7)
                                except Exception as e:
                                    output = "Error while running command during interactive session: %s" %(str(e))
                                    self.event_logger(message=output)                                                                                
                            else:                            
                                func = self.registered_task(func=job)
                                if func:                                    
                                    data = func(**args_dict)
                                    filtered_data = self.filter_fields(data,inc=args_dict.get("inc",[]),exc=args_dict.get("exc",[]))                                    
                                    output = self.to_tabulate(filtered_data,vertical=args_dict.get("vertical"))                                      
                                else:
                                    output = "Job does not exist."
                        else:
                            output = "Invalid format for job request!"                                    
                    else:
                        pass #// Empty cmd from server                                                                                                                        
            except Exception as e:
                output = "Error during interactive session: %s" %str(e)
                self.event_logger(message=output,log_type="error")                                                                                                
            finally:
                if response:
                    try: 
                        payload = { "dataset": {
                            "output":output,
                            "host_name": self.hostname,
                            "host_id":self.aid,
                            "id": response.get("id",None),
                            "context": {"cwd":str(os.getcwd()) + '>'}
                            }
                        }  
                        self.post_data("interactive", payload=payload)
                    except Exception as e:
                        self.event_logger(message="Unable to send command output during interactive session. Likely an encoding issue")                                            
        
        @should_we_run                                
        def manage_local_account_password(self,**kwargs):
            data = []
            if self.is_dc:
                return data   
            server = self.hostname                
            managed_accounts = []
            #// Get managed accounts ready for rotation
            request = self.get_data("manage/local/accounts")
            if request:
                managed_accounts = request.get("accounts",[])
                    
            for user in managed_accounts:
                username = user["username"]
                sid = user["sid"]
                
                password_length = user.get("password_length",20)                
                rotate_method = user.get("rotate_method","change").lower()
                old_password = user.get("old_password")
                reconcile = user.get("reconcile")
                disable = user.get("disable",False)                
                
                if rotate_method == "set":
                    # set user password
                    result = self.rotate_user_password(username,sid,server,"set",length=password_length,disable=disable)                    

                elif rotate_method == "change":                    
                    result = self.rotate_user_password(username,sid,server,"change",length=password_length,old_password=old_password,disable=disable)
                    
                    if not result["success"]:
                        if reconcile: # try to set pwd if a error occurs
                            result = self.rotate_user_password(username,sid,server,"set",length=password_length,disable=disable)                            
                            result["reconciled"] = True
                else:
                    result = []
                if result:
                    data.append(result)
            return data  

        @should_we_run                                
        def manage_ad_account_password(self,**kwargs):
            data = []
            if not self.domain_joined:
                return data                
            if self.sys_data["advaulter"] != 1:
                return data             
            server = None
            if not self.is_dc: # if not a DC, change server lookup 
                server = self.domain            
            managed_accounts = []
            #// Get managed accounts ready for rotation
            request = self.get_data("manage/ad/accounts")
            if request:
                managed_accounts = request.get("accounts",[])
            
            for user in managed_accounts:
                username = user["username"]
                sid = user["sid"]
                
                rotate_method = user.get("rotate_method","change").lower()
                old_password = user.get("old_password")
                reconcile = user.get("reconcile")
                
                password_length = user.get("password_length",20)                
                disable = user.get("disable",False)
                password_expires = user.get("password_expires",False)
                logon_workstations = user.get("logon_workstations",False)
                
                if rotate_method == "set":
                    # set user password                                        
                    result = self.rotate_user_password(username,sid,server,"set",local_account=False,
                        length=password_length,logon_workstations=logon_workstations,password_expires=password_expires,
                        disable=disable)

                elif rotate_method == "change":                    
                    result = self.rotate_user_password(username,sid,server,"change",old_password=old_password,
                        local_account=False,length=password_length,logon_workstations=logon_workstations,password_expires=password_expires,
                        disable=disable)
                    if not result["success"]:
                        if reconcile: # try to set pwd if a error occurs
                            result = self.rotate_user_password(username,sid,server,"set",local_account=False,
                                length=password_length,logon_workstations=logon_workstations,password_expires=password_expires,
                                disable=disable) 
                            result["reconciled"] = True
                else:
                    result = []
                if result:
                    data.append(result)
            return data              
        
        @should_we_run                        
        def get_netconnection(self,**kwargs):
            AF_INET6 = getattr(socket, 'AF_INET6', object())
            proto_map = {
                (AF_INET, SOCK_STREAM): 'tcp',
                (AF_INET6, SOCK_STREAM): 'tcp6',
                (AF_INET, SOCK_DGRAM): 'udp',
                (AF_INET6, SOCK_DGRAM): 'udp6',
            }
            username = None
            domain = None
            sid = None
            atype = None
            exe = None
            name = None
            cmdline = None
            data = []
            #proc_names = {}
            try:            
                # for p in psutil.process_iter(attrs=['pid', 'name']):
                    # proc_names[p.info['pid']] = p.info['name']
                for c in psutil.net_connections():                    
                    raddr="-"
                    if c.raddr:
                        raddr=c.raddr.ip   
                    if raddr != self.cmdserver:
                        p = psutil.Process(c.pid)
                        try:
                            rport = int(c.raddr.port)
                        except:
                            rport = 0
                        try:
                            lport = int(c.laddr.port)
                        except:
                            lport = 0
                        try:
                            u = p.username().lower()
                            username = u.split("\\")[1]
                            user = self.lookup_account(username)                        
                            if user:
                                domain = user["domain"]
                                sid = user["sid"]
                                atype = user["account_type"]
                        except:
                            pass
                        try:
                            exe = p.exe()
                            name = p.name()
                            cmdline = p.cmdline()
                        except:
                            pass                            
                                                
                        if "NONE" not in c.status:                        
                            data.append({"host_name":self.hostname,"host_id":self.aid,"family":proto_map[(c.family, c.type)],"laddr":c.laddr.ip,"lport":lport,
                                "raddr":raddr,"rport":rport,"status":c.status,"pid":c.pid,"pname":name,
                                "username":username,"sid":sid,"domain":domain,"exe":exe,"image":name,"cmdline":cmdline,"account_type":atype
                            })
            except Exception:
                pass
            return data 

        @should_we_run                
        def get_auditkeys(self,**kwargs):
            data = []        
            keys = []
            get_keys = self.get_data("registry/auditkeys")            
            if get_keys:
                keys = get_keys.get("keys")
                
            if keys and isinstance(keys,list):
                hive = Registry_Read("hklm")            
                for key in keys:
                    result = hive.list_contents(key) or "None"
                    data.append({"key":str(key),"value":str(result),"host_name":self.hostname,"host_id":self.aid})
            return data               
                
        @should_we_run                
        def get_runkeys(self,**kwargs):
            data = []        
            keys = []
            get_keys = self.get_data("registry/runkeys")
            if get_keys:
                keys = get_keys.get("keys")
                
            if keys:
                hive = Registry_Read("hklm")            
                for key in keys:
                    result = hive.list_contents(key) or "None"
                    data.append({key:result})
            return data

        @should_we_run                
        def get_disk(self,**kwargs):
            data = []
            for part in psutil.disk_partitions(all=1):            
                if os.name == 'nt':
                    if 'cdrom' in part.opts or part.fstype == '':
                        continue
                usage = psutil.disk_usage(part.mountpoint)
                data.append({"host_name":self.hostname,"host_id":self.aid,"device":part.device,"total":bytes2human(usage.total),"used":bytes2human(usage.used),
                    "free":bytes2human(usage.free),"used_percent":int(usage.percent),"fs_type":part.fstype,"mount":part.mountpoint
                })                       
            return data

        @should_we_run                
        def get_memory(self,**kwargs):
            data = []
            virt = psutil.virtual_memory()
            data.append({"host_name":self.hostname,"host_id":self.aid,"total":bytes2human(virt.total),"used":bytes2human(virt.used),"free":bytes2human(virt.free),
                "shared":bytes2human(getattr(virt, 'shared', 0)),"buffers":bytes2human(getattr(virt, 'buffers', 0)),
                "cache":bytes2human(getattr(virt, 'cached', 0))
            })            
            return data          

        @should_we_run                
        def get_regkey(self,hive="hklm",keypath="",**kwargs):
            data = []
            keypath = keypath.lstrip("\\")
            obj = Registry_Read(hive)
            results = obj.list_contents(keypath)
            
            if results is None and console:
                return "Key does not exist."   
            elif not results and console:
                return "No data for key."
                
            data.append(results)                             
            return data   
            
        @should_we_run                
        def get_updates(self,only_missing=False,**kwargs):
            data = []
            update_types = {1:"software",2:"driver"}
            wua = win32com.client.Dispatch("Microsoft.Update.Session")
            update_seeker = wua.CreateUpdateSearcher()    
            search_string = "Type='Software' or Type='Driver'"
            
            if only_missing:
                search_string = "IsInstalled=0 and " + search_string
            search_update = update_seeker.Search(search_string)
            
            _ = win32com.client.Dispatch("Microsoft.Update.UpdateColl")

            for update in search_update.Updates:  
                try:
                    categories = [item.Name for item in update.Categories]
                    temp= {
                        "main_category":categories[0],
                        "update_type":update_types.get(update.Type,1),
                        "installed":update.IsInstalled,
                        "downloaded":update.IsDownloaded,
                        "severity":update.MsrcSeverity,
                        "needsreboot":update.RebootRequired,
                        "mandatory":update.IsMandatory,
                        "title":update.Title,
                        "hidden":update.IsHidden,
                        "description":update.Description,
                        "guid":update.Identity.UpdateID,
                        "kbs":str(['KB' + item for item in update.KBArticleIDs]),
                        'categories': str(categories),
                        "last_published":str(update.LastDeploymentChangeTime),
                        "host_name":self.hostname,
                        "host_id":self.aid
                    } 
                    data.append(temp)
                except:
                    pass
            return data
    
        @should_we_run                
        def get_printer(self,**kwargs):
            flag_map = {
                512:"Busy",
                4194304:"DoorOpen",
                2:"Error",	
                32768:"Initializing",	
                256:"IOActive",	
                32:"ManualFeed",	
                0:"None",	
                4096:"NotAvailable",	
                262144:"NoToner",	
                128:"Offline",	
                2097152:"OutOfMemory",	
                2048:"OutputBinFull",	
                524288:"PagePunt",	
                8:"PaperJam",	
                16:"PaperOut",	
                64:"PaperProblem",	
                1:"Paused",	
                4:"PendingDeletion",	
                16777216:"PowerSave",	
                1024:"Printing",	
                16384:"Processing",	
                8388608:"Unknown",	
                131072:"TonerLow",	
                1048576:"UserActionReq",	
                8192:"Waiting",	
                65536:"WarmingUp"
            }	        
            data = []
            try:
                for printer in win32print.EnumPrinters(win32print.PRINTER_ENUM_LOCAL | win32print.PRINTER_ENUM_CONNECTIONS,None,1):
                    flags,description,name,path = printer
                    data.append({"host_name":self.hostname,"host_id":self.aid,"flags":flags,"status":flag_map.get(flags,"Unknown"),
                        "description":description,"name":name,"path":path})         
            except:
                pass
            return data

        @should_we_run                
        def get_pipe(self,**kwargs):
            data = []
            try:
                path=r"\\.\pipe\\"
                for each in os.listdir(path):
                    data.append({"name":each,"host_name":self.hostname,"host_id":self.aid})
            except:
                pass
            return data
            
        @should_we_run                        
        def get_service(self,**kwargs):
            data = []
            
            start_map = {
                0:"kernelboot",
                1:"iosystem",
                2:"automatic",
                3:"manual",
                4:"disabled",
            }
            stype_map = {
                4:"Adaptor",
                2:"FileSystemDriver",
                256:"InteractiveProcess",
                1:"KernelDriver",
                8:"RecognizerDriver",
                16:"OwnProcess",
                32:"ShareProcess",
                224:"Denied"
            }
            status_map = {
                1:"Stopped",
                2:"StartPending",
                3:"StopPending",
                4:"Running",
                5:"ContinuePending",
                6:"PausePending",
                7:"Paused"
            } 
            resume = 0
            accessSCM = win32con.GENERIC_READ
            accessSrv = win32service.SC_MANAGER_ALL_ACCESS

            #Open Service Control Manager
            hscm = win32service.OpenSCManager(None, None, accessSCM)    
            
            for svc in win32service.EnumServicesStatus(hscm):
                temp = {}
                try:        
                    s = win32service.OpenService(hscm, svc[0], win32service.SERVICE_ALL_ACCESS)
                    cfg = win32service.QueryServiceConfig(s)               
                    if cfg:
                        serviceType,startType,errorControl,binaryPath,loadGroup,tagId,dependencies,startName,displayName = cfg
                        
                        # Some parsing to get the image and arguments.. worth the time since its rich data
                        try:
                            basepath = os.path.dirname(binaryPath).replace('"',"")          
                            bn = os.path.basename(binaryPath).split(" ")
                            image = bn[0].replace('"',"")
                            arguments = " ".join(bn[1:])                    
                            if image:
                                temp["image"] = image
                                abspath = os.path.join(basepath,image)
                                # if "system32" not in abspath.lower():
                                    # temp["hash"] = self.get_hash(abspath,only_hash=True)                        
                                
                            if arguments:
                                temp["arguments"] = arguments
                        except:
                            pass

                        temp["registry_name"] = win32service.GetServiceKeyName(s,displayName)
                        temp["service_type"] = stype_map.get(serviceType,"unknown")
                        temp["start_type"] = start_map.get(startType,"unknown")
                        temp["dependencies"] = dependencies
                        temp["display_name"] = displayName 
                        temp["description"] = win32service.QueryServiceConfig2(s,1)
                        temp["command"] = binaryPath

                        if startName:
                            if "\\" in startName:
                                startName = startName.split("\\")[1].lower()
                            temp["username"] = startName.lower()
                            if startName != "localsystem": #no account mapping, save a lookup
                                try:
                                    user = self.lookup_account(startName)
                                    if user:
                                        temp = {**temp,**user}     
                                except:
                                    pass                
                        try:           
                            status = win32service.QueryServiceStatus(s)
                            temp["status"] = status_map.get(status[1],"unknown")
                        except:
                            pass 
                        
                except Exception as e:
                    pass
                finally:
                    win32service.CloseServiceHandle(s)
                if temp:
                    temp["host_name"] = self.hostname
                    temp["host_id"] = self.aid
                    data.append(temp)                
            return data        
            
        @should_we_run   
        def get_process(self,collect_parent=False,collect_children=False,**kwargs):
            dataset = []
            attrs = ['cwd', 'pid','exe','name','num_handles',
                'num_threads','ppid', 'status','username','cmdline']
                
            for proc in psutil.process_iter():
                try:
                    temp = proc.as_dict(attrs=attrs)
                    temp["host_name"] = self.hostname 
                    temp["host_id"] = self.aid
                    # temp["is_running"] = proc.is_running()
                    temp["create_time"] = self.timestamp_to_readable(proc.create_time())
                    temp["memory_percent"] = round(proc.memory_percent(),2)
                    temp["cpu_percent"] = round(proc.cpu_percent(),2)
                    
                    try:
                        if temp.get("name"):                
                            temp["image"] = temp.get("name")
                        # if temp.get("exe"):
                            # temp["exe"] = temp.get("exe")
                            # if "program files" not in exe.lower():                        
                                # temp["hash"] = self.get_hash(exe,only_hash=True)
                    except:
                        pass
                    try: # get sid and domain
                        name = proc.username().lower()
                        name = name.split("\\")[1]
                        temp["username"] = name
                        user = self.lookup_account(name)                        
                        if user:
                            temp = {**temp,**user}        
                    except:
                        pass
                    
                    if collect_parent:
                        ## Get parents  
                        parent_list = []
                        for parent in proc.parents():
                            parent_dict = {"pid":parent.pid}
                            try:
                                if hasattr(parent,"name"):
                                    parent_dict["image"] = parent.name()  
                                if hasattr(parent,"create_time"):
                                    parent_dict["create_time"] = self.timestamp_to_readable(parent.create_time())
                                if hasattr(parent,"exe"):
                                    parent_dict["command"] = parent.exe()                             
                            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                                pass
                            if parent_dict:
                                parent_list.append(parent_dict)
                        # Add parents
                        temp["parents"] = parent_list
                        temp["parent_count"] = len(parent_list)  
                        
                    if collect_children:
                        ## Get children
                        child_list = []
                        for child in proc.children():
                            child_dict = {"pid":child.pid}
                            try:
                                if hasattr(child,"name"):
                                    child_dict["image"] = child.name()  
                                if hasattr(child,"create_time"):
                                    child_dict["create_time"] = self.timestamp_to_readable(child.create_time())
                                if hasattr(child,"exe"):
                                    child_dict["command"] = child.exe()                         
                            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                                pass
                            if child_dict:
                                child_list.append(child_dict)
                        # Add children
                        temp["children"] = child_list
                        temp["children_count"] = len(child_list)   
                    #temp.pop("exe",None)         
                    temp.pop("name",None)
                    # Add process to list
                    dataset.append(temp)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass                    
            return dataset    

        @should_we_run                
        def get_patch(self,**kwargs):
            data = self.invoke_wmi(wclass="win32_quickfixengineering",**kwargs)                        
            return data 

        def get_local_group_membership(self,user):
            try:
                return win32net.NetUserGetLocalGroups(None,user)
            except:
                return []
        
        @should_we_run   
        def get_user(self,collect_groups=True,override=False,**kwargs):
            '''Collect all user accounts (domain and local) on a host'''
            data = []             
            if not self.is_dc or override:            
                seen_sid = []
                results, total, resume = win32net.NetLocalGroupEnum("localhost", 1, 0)
                for group in results:
                    memberdata, total, memberresume = win32net.NetLocalGroupGetMembers("localhost", group['name'], 2, 0)
                    for member in memberdata:
                        if member["sidusage"] == 1:
                            sid = win32security.ConvertSidToStringSid(member['sid'])
                            if sid not in seen_sid:
                                seen_sid.append(sid)
                                domainandname = member["domainandname"]
                                try:
                                    domain,username = domainandname.split("\\")
                                except:
                                    domain = domainandname
                                    username = domainandname
                                account = self.lookup_account(username,collect_info=True)
                                account["host_name"] = self.hostname
                                account["host_id"] = self.aid
                                if collect_groups:
                                    account["groups"] = self.get_local_group_membership(username)
                                data.append(account)                        
            return data
            
        @should_we_run     
        def get_group(self,collect_users=True,override=False,**kwargs):
            '''Collect all local groups and members'''
            data = []         
            if not self.is_dc or override:                    
                sidtype_map = {
                    "1":"user",
                    "2":"group",
                    "5":"special"
                }
                results, total, resume = win32net.NetLocalGroupEnum("localhost", 1, 0)
                for group in results:
                    temp = {"host_name":self.hostname,"host_id":self.aid,"group":group["name"],"description":group["comment"],"members":[],"account_type":"group","local_account":True,"domain_accounts":0}
                    memberdata, total, memberresume = win32net.NetLocalGroupGetMembers("localhost", group['name'], 2, 0)
                    temp["members_count"] = total
                    if collect_users:
                        # enum members in each group
                        for member in memberdata:
                            local_account = True
                            domainandname = member["domainandname"]
                            try:
                                domain,username = domainandname.split("\\")
                            except:
                                domain = domainandname
                                username = domainandname   
                            sid = win32security.ConvertSidToStringSid(member['sid'])
                            sidtype = str(member["sidusage"])
                            if not self.find_account_by_name_locally(username) and sidtype != "5":
                                local_account = False
                                temp["domain_accounts"] += 1
                            # add member
                            temp["members"].append({"sid":sid,"domain":domain,"username":username,
                                "local_account":local_account,"account_type":self.get_accounttype(sidtype)
                            })
                    data.append(temp)
            return data

        @should_we_run                
        def get_system(self,**kwargs):
            attrs = ["name","model","bootupstate","caption","currenttimezone","description",
                "dnshostname","domain","domainrole","manufacturer","model","partofdomain",
                "numberoflogicalprocessors","numberofprocessors","primaryownername","roles",
                "status","systemfamily","systemtype"]
            data = self.invoke_wmi(wclass="win32_computersystem",attrs=attrs,**kwargs) 
            return data 
            
        # @should_we_run                
        # def get_profile(self,**kwargs):
            '''Deprecated by logon users'''
            # data = self.invoke_wmi(wclass="win32_networkloginprofile",**kwargs)                         
            # return data 

        @should_we_run                
        def get_logon(self,days=15,**kwargs):  
            data = []
            logon_map = {
                0:"system",
                2:"interactive",
                3:"network",
                4:"batch",
                5:"service",
                6:"proxy",
                7:"unlock",
                8:"network_cleartext",
                9:"new_creds",
                10:"rdp",
                11:"cached_creds",
                12:"cached_rdp",
                13:"cached_unlock"
            } 
            data_keys = ["logondomain","authenticationpackage","logontype","logonid",
                "logontime","logonserver","upn"]
            #today = datetime.today()
            try:
                sessions = win32security.LsaEnumerateLogonSessions()
                for session in sessions:
                    sn_info = win32security.LsaGetLogonSessionData(session)
                    username = sn_info.get("UserName",None)
                    blacklist_users = ["DWM","$","IUSR","UMFD","LOCAL SERVICE","ANONYMOUS LOGON"]
                    if username and not any(x in username for x in blacklist_users):
                        # logon_time = sn_info.get("LogonTime")
                        # if logon_time:
                            # logon_time = logon_time.replace(tzinfo=None)                
                            # if ((today - logon_time) < timedelta(days=days)):
                                temp = self.lookup_account(username,collect_info=True)                                
                                temp["host_name"] = self.hostname
                                temp["host_id"] = self.aid
                                
                                for key,value in sn_info.items():
                                    key = key.lower()                
                                    if key in data_keys:
                                        if key == "logontype":
                                            value = logon_map.get(value,"unknown")
                                        temp[key] = str(value)
                                if temp:
                                    data.append(temp)                            
            except Exception as e:
                pass
            finally:            
                return data                       

        @should_we_run                
        def get_netadapter(self,**kwargs):
            attrs=["caption","defaultipgateway","description","dhcpenabled",
                "dnshostname","dnsserversearchorder","dnsdomainsuffixsearchorder",
                "ipaddress","ipenabled","ipsubnet","macaddress","servicename"]

            data = self.invoke_wmi(wclass="win32_networkadapterconfiguration",attrs=attrs,**kwargs)                          
            return data  

        @should_we_run                
        def get_share(self,**kwargs):
            data = []
            share_map = {
                0:"disk drive",
                1:"print queue",
                2:"device",
                3:"IPC",
                2147483648:"disk drive admin",
                2147483649:"print queue admin",
                2147483650:"device admin",
                2147483651:"ipc admin",
            }
            wmi_shares = self.invoke_wmi(wclass="win32_share",**kwargs)            
            try:
                api_share,total,resume = win32net.NetShareEnum(None,2,0)
                
                for share in wmi_shares:
                    name = share.get("name")
                    for s in api_share:
                        s_name = s.get("netname")
                        if name == s_name:
                            for k,v in s.items():
                                if k in ("current_uses","passwd","type","permissions"):
                                    share[k] = v
                                if k in ("type"):
                                    share["type_str"] = share_map.get(v,"None")
                    data.append(share)            
                return data 
            except:
                return wmi_shares
        
        @should_we_run                        
        def get_startup(self,**kwargs):
            attrs = ["caption","command","description","location","name","user","usersid"]
            result = self.invoke_wmi(wclass="win32_startupcommand",attrs=attrs,**kwargs)

            data = []
            for command in result:
                user = command.get("user")
                temp = {
                    "image":command.get("caption"),
                    "command":command.get("command"),
                    "description":command.get("description"),
                    "location":command.get("location"),
                    "sid":command.get("usersid"),
                    "username":user,
                    "host_name":self.hostname,
                    "host_id":self.aid
                }
                try:
                    if "\\" in user:
                        domain,username = user.split("\\")
                        temp["domain"] = domain
                        temp["username"] = username
                except:
                    pass
                data.append(temp)            
            return data 
            
        def invoke_wmi(self,wclass=None,attrs=[],filter={},**kwargs):
        
            '''
            :Usage - invoke_wmi(wmi_class="win32_service",filter={},inc=include,console=None,vertical=False)
            '''
            valid_classes = ["win32_computersystem","win32_useraccount","win32_quickfixengineering",
                "win32_networkloginprofile","win32_group","win32_service","win32_loggedonuser",
                "win32_process","win32_startupcommand","win32_share","win32_networkadapterconfiguration"
            ] 
            
            if wclass is None:
                raise Exception("WMI class parameter is required!")
            if wclass.lower() not in valid_classes:
                raise Exception("WMI class is not available or invalid!")

            data = self.wmi_query(wclass,attrs=attrs,filter=filter)
            
            if not isinstance(data,list):
                data = [data]            
            
            return data

        def wmi_query(self,subclass,attrs=[],filter={}):
            '''
            WMI function for calling specific classes
            '''  
            data = []
            logon_map = {
                0:"system",
                2:"interactive",
                3:"network",
                4:"batch",
                5:"service",
                6:"proxy",
                7:"unlock",
                8:"network_cleartext",
                9:"new_creds",
                10:"rdp",
                11:"cached_creds",
                12:"cached_rdp",
                13:"cached_unlock"
            }               
            if subclass in ("win32_useraccount","win32_group") and not filter: #legacy
                filter={"LocalAccount":True} 
            elif subclass in ("win32_networkadapterconfiguration") and not filter:
                filter={"IPEnabled":True}            
                
            results = getattr(self.c,str(subclass))(**filter)            
            if results:
                for record in results:
                    temp = {}
                    for each in record.Properties_:
                        key = each.Name.lower()
                        if not attrs:
                            temp[key] = each.Value                            
                        elif key in attrs:
                            temp[key] = each.Value
                    if temp:
                        temp["host_name"] = self.hostname
                        temp["host_id"] = self.aid
                        data.append(temp)
            return data                  

        @should_we_run        
        def get_platform(self,**kwargs):            
            dynamic_attr = {
                "id": self.aid,
                "version": self.version,
                "install_group": self.group,
                "console": self.cmdurl,             
                "memory":bytes2human(int(psutil.virtual_memory().total / 1024)),                
                "last_boot": self.timestamp_to_readable(psutil.boot_time()),  
                "local_addr": self.get_ip(),                
            }
            data = [{**self.sys_data,**dynamic_attr}]
            return data 

        def get_event(self,logtype="Security",eventid=[4624],hours=1,limit=20,start=None,end=None,**kwargs):
            '''
            Usage: get_event(start="2019-02-05 16:39:45",end="2019-02-06 19:32:45")
            '''
            data = []
            server = 'localhost'
            hand = win32evtlog.OpenEventLog(server,logtype)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
            total = win32evtlog.GetNumberOfEventLogRecords(hand)
              
            eventid = [int(x) for x in eventid] 
            date_format = "%Y-%m-%d %H:%M:%S"

            _from = (datetime.now() - timedelta(hours=hours)).strftime(date_format)
            _from = datetime.strptime(_from, date_format)    
            _to = (datetime.now() - timedelta(hours=0)).strftime(date_format)
            _to = datetime.strptime(_to, date_format)  
            count=1
            done=0
            while done == 0:
                events = win32evtlog.ReadEventLog(hand, flags,0)
                if events:
                    for event in events:
                        if eventid and event.EventID not in eventid:
                            break
                            
                        generated=str(event.TimeGenerated)

                        event_time = datetime.strptime(generated, date_format)                               
                        
                        if count > limit:
                            done=1
                            break   
                            
                        if start:
                            _from = datetime.strptime(start, date_format)   
                            
                        if end:
                            _to = datetime.strptime(end, date_format)                       
                        
                        if event_time <= _from:
                            done=1
                            break 
                                                
                        event_message = (win32evtlogutil.SafeFormatMessage(event, logtype))

                        try:
                            msg = event_message.splitlines()[0]
                        except:
                            msg = "None"

                        extra_fields={
                            "eventtype": event.EventType,
                            "source": event.SourceName,
                            "recordnumber": event.RecordNumber,
                            "generated": generated,
                            "written": event.TimeWritten.Format(),
                            "logtype": logtype,
                            "eventid": event.EventID,
                            "category": event.EventCategory,
                            "message": event_message,
                            "summary":msg,
                            "host_name": self.hostname,
                            "host_id":self.aid                            
                        } 
                        if event_time <= _to:
                            data.append(extra_fields)
                            count+=1
                    if done:
                        win32evtlog.CloseEventLog(hand)                         
                        break             
            return data    
                
        @should_we_run        
        def get_software(self,**kwargs):
            data = []
            hive_dict = {
                "hive1": (HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY),
                "hive2": (HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY)
            }            
            for name,values in hive_dict.items():
                hive,flag = values
                aReg = ConnectRegistry(None, hive)
                aKey = OpenKey(aReg, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                                      0, KEY_READ | flag)
                count_subkey = QueryInfoKey(aKey)[0]
                for i in range(count_subkey):
                    software = {}
                    software_key_names = ["DisplayName","DisplayVersion","Version","Publisher","UninstallString",
                        "EstimatedSize","InstallDate","ModifyPath","InstallSource","MajorVersion","MinorVersion"
                    ]                        
                    try:
                        asubkey_name = EnumKey(aKey, i)
                        asubkey = OpenKey(aKey, asubkey_name)
                        for key in software_key_names:
                            try:                                    
                                software[key.lower()] = QueryValueEx(asubkey, key)[0]
                            except:
                                continue
                        if software:
                            software["host_name"] = self.hostname
                            software["host_id"] = self.aid
                            data.append(software)
                    except:
                        continue
            return data                              

        @should_we_run        
        def get_netsession(self,**kwargs):
            data = []
            for session in win32net.NetSessionEnum(502):
                client = session.get("client_name")
                if client:
                    session["client_host"] = self.resolve_ip(client)
                session["host_name"] = self.hostname
                session["host_id"] = self.aid
                data.append(session)
            return data    
                
        @should_we_run                       
        def get_schtask(self,**kwargs):
            data = []
            TASK_ENUM_HIDDEN = 1
            TASK_STATE = {0: 'Unknown',
                          1: 'Disabled',
                          2: 'Queued',
                          3: 'Ready',
                          4: 'Running'} 
            TASK_RESULT = {
                0:"Completed successfully.",
                1:"Incorrect/unknown function called. 2 File not found.",
                10:"The environment is incorrect.",
                267008:"Rready to run at next scheduled time.", 
                267009:"Currently running.", 
                267010:"Will not run at scheduled times b/c it is disabled.", 
                267011:"Task has not yet run.", 
                267012:"No more runs scheduled.", 
                267013:"Properties required have not been set.", 
                267014:"The last run of the task was terminated by the user.",
                267015:"Missing triggers or existing triggers are disabled/not set.",
                2147750671:"Credentials became corrupted.", 
                2147750687:"Instance of task already running.",
                2147943645:"Service not available.", 
                3221225786:"Terminated as a result of a CTRL+C.",
                3228369022:"Unknown software exception."
            }
            system_root = win32api.GetWindowsDirectory()    
            scheduler = win32com.client.Dispatch('Schedule.Service')
            scheduler.Connect()
            n = 0
            folders = [scheduler.GetFolder('\\')]
            while folders:
                folder = folders.pop(0)
                folders += list(folder.GetFolders(0))
                tasks = list(folder.GetTasks(TASK_ENUM_HIDDEN))
                n += len(tasks) 
                for task in tasks:
                    temp = {}
                    try:
                        settings = task.Definition.Settings
                        try:    
                            xml = task.XML
                            result = xmltodict.parse(xml)
                            try:
                                sid = result["Task"]["Principals"]["Principal"]["UserId"]
                            except KeyError:
                                sid = None                       
                            try:
                                run_level = result["Task"]["Principals"]["Principal"]["RunLevel"]
                                temp["run_level"] = run_level
                            except KeyError:
                                run_level = None
                            try:
                                command = result["Task"]["Actions"]["Exec"]["Command"]
                            except KeyError:
                                command = None
                            try:
                                arguments = result["Task"]["Actions"]["Exec"]["Arguments"]
                                temp["arguments"] = arguments
                            except KeyError:
                                arguments = None
                            
                            if command:
                                if "%windir%" in command.lower():
                                    command = command.replace("%windir%",system_root)
                                if "%systemroot%" in command.lower():                    
                                    command = command.replace("%systemroot%",system_root) 
                                    command = command.replace("%SystemRoot%",system_root) 
                                    
                                temp["image"] = os.path.basename(command).strip()                   
                                temp["command"] = "{} {}".format(command,arguments or "").strip()
                                temp["base_command"] = command
                                if "system32" not in command.lower():
                                    temp["hash"] = self.get_hash(command,only_hash=True)                                
                                
                            if sid:  
                                b_sid = win32security.ConvertStringSidToSid(sid)
                                username, domain, atype = win32security.LookupAccountSid(None,b_sid)
                                temp["sid"] = sid
                                temp["username"] = username.lower()
                                temp["domain"] = domain
                                temp["account_type"] = self.get_accounttype(atype)
                        except:
                            pass                    
                        com_dict = {
                            "folder":task.Path,
                            "hidden":settings.Hidden,
                            "state":TASK_STATE.get(task.State,"unknown"),
                            "last_run":str(task.LastRunTime),
                            "last_result":TASK_RESULT.get(task.LastTaskResult,"unknown"),
                            "enabled":task.Enabled,
                            "next_run":str(task.NextRunTime),
                            "host_name": self.hostname,
                            "host_id":self.aid
                        }
                        temp = {**temp,**com_dict}
                    except:
                        pass
                    if temp:
                        data.append(temp) 
            return data    
                                  
        #-----------------------------------------------ACTIVE DIRECTORY COLLECTION-----------------------------------------------          
        @should_we_run        
        def get_ad_domain(self,props=None,post_limit=20,**kwargs):
            #win32security.DsGetDcName() --> More info to grab
            data = []
            if self.sys_data["adcollector"] != 1:
                return data
            if not self.domain_joined:
                return data                
            count = 0                        
            if not props:
                props=['dc', 'instancetype','objectcategory', 'objectclass', 
                    'creationtime', 'distinguishedname', 'dscorepropagationdata', 
                    'fsmoroleowner', 'gplink', 'iscriticalsystemobject', 
                    'minpwdage', 'minpwdlength', 'modifiedcount', 'modifiedcountatlastprom', 
                    'ms-ds-machineaccountquota', 'msds-alluserstrustquota', 'msds-behavior-version', 
                    'msds-expirepasswordsonsmartcardonlyaccounts', 'msds-isdomainfor', 
                    'msds-perusertrustquota', 'msds-perusertrusttombstonesquota', 'name', 'nextrid', 
                    'ridmanagerreference', 'serverstate', 
                    'systemflags', 'uascompat', 'usnchanged', 'usncreated', 'whenchanged', 'whencreated']   
            root = active_directory.root()
            obj = self.iterate_props(root,props)
            if obj:
                try:
                    obj["domain"] = self.parse_domain_from_dn(root.distinguishedname)
                except:
                    pass   
                count+=1            
                if count > post_limit: # limit amount assets 
                    count = 0
                    results = {"task":"get-ad-domain","dataset":data}
                    self.post_data(os.path.join("collection","get-ad-domain"), payload=results)

                    data.clear() # clear list  
                    # check stop
                    self.checkStop(wait_time=100)                    
                data.append(obj)
            return data
    
        @should_we_run        
        def get_ad_dc(self,props=None,post_limit=20,**kwargs):
            data = []
            if self.sys_data["adcollector"] != 1:
                return data 
            if not self.domain_joined:
                return data                
            count = 0                        
            if not props:    
                props = ['instancetype', 'objectcategory', 
                    'objectclass', 'cn', 'distinguishedname', 'dnshostname', 'name', 
                    'serverreference', 'showinadvancedviewonly', 'systemflags', 'usnchanged', 
                    'usncreated', 'whenchanged', 'whencreated']
            for master in active_directory.root().masteredBy: 
                count+=1            
                obj = self.iterate_props(master.Parent,props)
                if obj:  
                    try:
                        obj["domain"] = self.parse_domain_from_dn(master.Parent.distinguishedname)
                    except:
                        pass                
                    if count > post_limit: # limit amount assets 
                        count = 0
                        results = {"task":"get-ad-dc","dataset":data}
                        self.post_data(os.path.join("collection","get-ad-dc"), payload=results)

                        data.clear() # clear list   
                        # check stop
                        self.checkStop(wait_time=100)                        
                    data.append(obj)    
            return data

        @should_we_run        
        def get_ad_gpo(self,props=None,post_limit=20,**kwargs):
            data = []
            if self.sys_data["adcollector"] != 1:
                return data
            if not self.domain_joined:
                return data
            count = 0                        
            if not props:
                props = ['cn', 'instancetype', 'objectcategory', 'objectclass', 'displayname', 
                    'distinguishedname', 'gpcfilesyspath', 'gpcfunctionalityversion', 
                    'gpcmachineextensionnames', 'gpcuserextensionnames', 'iscriticalsystemobject', 
                    'name', 'showinadvancedviewonly', 'systemflags', 'usnchanged', 'usncreated', 
                    'versionnumber', 'whenchanged', 'whencreated']
            session = self.requests_session()            
                    
            for gpo in active_directory.search(objectClass="groupPolicyContainer"):  
                count+=1
                obj = self.iterate_props(gpo,props)
                if obj:
                    try:
                        obj["domain"] = self.parse_domain_from_dn(gpo.distinguishedname)
                    except:
                        pass                
                    if count > post_limit: # limit amount assets 
                        count = 0
                        results = {"task":"get-ad-gpo","dataset":data}
                        self.post_data(os.path.join("collection","get-ad-gpo"), session=session,payload=results)

                        data.clear() # clear list  
                        # check stop
                        self.checkStop(wait_time=100)                        
                    data.append(obj)
            return data

        @should_we_run        
        def get_ad_sysvol(self,post_limit=20,**kwargs):    
            '''Collect all files and ACL data in sysvol'''
            data = []
            if self.sys_data["adcollector"] != 1:
                return data 
            if not self.domain_joined:
                return data
            count = 0
            session = self.requests_session()            
            
            pdc = win32net.NetGetDCName() # get pdc
            if pdc:
                sysvol = os.path.join(pdc,"sysvol")
                
                for file in self.enum_directory(sysvol):
                    file_data = self.get_file_details(file)
                    acl_data = GetFileAcl(file).show_acls()
                    data.append({**file_data,**acl_data,"hash":self.get_hash(file,only_hash=True),"host_name":self.hostname,"host_id":self.aid})
                    if count > post_limit: # limit amount assets 
                        count = 0
                        results = {"task":"get-ad-sysvol","dataset":data}
                        self.post_data(os.path.join("collection","get-ad-sysvol"), session=session,payload=results)

                        data.clear() # clear list   
                        # check stop
                        self.checkStop(wait_time=100)                    
            return data            

        @should_we_run        
        def get_ad_ou(self,props=None,post_limit=20,**kwargs):
            data = []
            if self.sys_data["adcollector"] != 1:
                return data
            if not self.domain_joined:
                return data                
            count = 0                        
            if not props:
                props = ['instancetype', 'objectcategory', 'objectclass', 'ou', 
                    'description', 'distinguishedname', 'gplink', 'iscriticalsystemobject', 
                    'name', 'systemflags', 'usnchanged', 'usncreated', 'whenchanged', 'whencreated']
            session = self.requests_session()            
                    
            for ou in active_directory.search(objectClass="organizationalunit"):
                count+=1            
                obj = self.iterate_props(ou,props)
                if obj:
                    try:
                        obj["domain"] = self.parse_domain_from_dn(ou.distinguishedname)                        
                    except:
                        pass                
                    if count > post_limit: # limit amount assets 
                        count = 0
                        results = {"task":"get-ad-ou","dataset":data}
                        self.post_data(os.path.join("collection","get-ad-ou"), session=session,payload=results)
                        
                        data.clear() # clear list   
                        # check stop
                        self.checkStop(wait_time=100)                        
                    data.append(obj)                        
            return data

        @should_we_run        
        def get_ad_computer(self,props=None,walk=True,flatten=False,post_limit=20,filter={},**kwargs):
            data = []
            if self.sys_data["adcollector"] != 1:
                return data
            if not self.domain_joined:
                return data                
            count = 0                        
            if not props:
                props = ['cn', 'instancetype', 'objectcategory', 
                    'objectclass', 'samaccountname', 'badpasswordtime', 'distinguishedname', 
                    'dnshostname', 'lastlogoff', 'lastlogon', 'lastlogontimestamp', 'logoncount', 
                    'msds-supportedencryptiontypes', 'name', 'operatingsystem', 'operatingsystemservicepack', 
                    'operatingsystemversion', 'primarygroupid', 'pwdlastset', 'samaccounttype', 
                    'serviceprincipalname', 'useraccountcontrol', 'usnchanged', 'usncreated', 
                    'whenchanged', 'whencreated']
            session = self.requests_session()            
                    
            for computer in active_directory.search(objectClass="computer",**filter):
                count+=1            
                obj = self.iterate_props(computer,props)
                if obj:  
                    try:
                        obj["domain"] = self.parse_domain_from_dn(computer.distinguishedname)
                    except:
                        pass
                    obj["name"] = "{}.{}".format(computer.name,obj.get("domain",self.domain)).lower()                        
                
                    if walk:
                        members = self.ad_walk(computer,flatten=flatten)
                        obj = {**obj,**members} 
                    if count > post_limit: # limit amount of assets 
                        count = 0
                        results = {"task":"get-ad-computer","dataset":data}
                        self.post_data(os.path.join("collection","get-ad-computer"), session=session,payload=results)
                        
                        data.clear() # clear list  
                        # check stop
                        self.checkStop(wait_time=100)                        
                    data.append(obj)            
            return data

        @should_we_run        
        def get_ad_user(self,props=None,walk=True,flatten=False,filter={},post_limit=20,**kwargs):
            data = []
            if self.sys_data["adcollector"] != 1:
                return data            
            if not self.domain_joined:
                return data                
            count = 0            
            if not props:
                props = ["cn","objectsid","lastlogon","lastlogoff","logoncount","lastlogontimestamp","description",
                    "badpasswordtime","samaccountname","samaccountType","useraccountcontrol","userprincipalname",
                    "distinguishedname","pwdlastset","whencreated","whenchanged","primarygroupid","displayname","admincount",
                    "title","department","serviceprincipalname"]
            session = self.requests_session()            
            for user in active_directory.search(objectClass="user",**filter): 
                count+=1
                obj = self.iterate_props(user,props)
                if obj:
                    try:
                        obj["domain"] = self.parse_domain_from_dn(user.distinguishedname)                    
                    except:
                        pass
                    obj["name"] = "{}.{}".format(user.name,obj.get("domain",self.domain)).lower()
                
                    if walk:
                        members = self.ad_walk(user,flatten=flatten)
                        obj = {**obj,**members}
                    if count > post_limit: # limit amount of assets 
                        count = 0
                        results = {"task":"get-ad-user","dataset":data}
                        self.post_data(os.path.join("collection","get-ad-user"), session=session,payload=results)
                        
                        data.clear() # clear list
                        # check stop
                        self.checkStop(wait_time=100)
                    data.append(obj)
            return data

        @should_we_run        
        def get_ad_group(self,props=None,walk=True,flatten=False,post_limit=20,filter={},**kwargs):
            '''
            walk - get membership and memberof
            flatten - recursively flatten tree to single depth
            filter - ex. {"cn":"domain users"}
            '''
            data = []
            if self.sys_data["adcollector"] != 1:
                return data
            if not self.domain_joined:
                return data
            count = 0            
            if not props:
                props = ['cn', 'grouptype', 'instancetype', 'objectcategory','objectsid', 
                    'objectclass', 'samaccountname', 'admincount','description', 'distinguishedname', 
                    'iscriticalsystemobject', 'name', 'samaccounttype', 'usnchanged', 'systemflags',
                    'usncreated', 'whenchanged', 'whencreated','mail']
            session = self.requests_session()            
                    
            for group in active_directory.search(objectClass="group",**filter):
                count+=1            
                obj = self.iterate_props(group,props)
                if obj:
                    try:
                        obj["domain"] = self.parse_domain_from_dn(group.distinguishedname)
                    except:
                        pass
                    obj["name"] = "{}.{}".format(group.name,obj.get("domain",self.domain)).lower()
                        
                    if walk:            
                        members = self.ad_walk(group,flatten=flatten)
                        obj = {**obj,**members} 
                    if count > post_limit: # limit amount of assets 
                        count = 0
                        results = {"task":"get-ad-group","dataset":data}
                        self.post_data(os.path.join("collection","get-ad-group"), session=session,payload=results)
                        
                        data.clear() # clear list
                        # check stop
                        self.checkStop(wait_time=100)                        
                    data.append(obj)
            return data
            
        @should_we_run        
        def get_ad_memberof(self, type="user",asset=None,props=None,**kwargs):
            type_map = {
                "user":active_directory.find_user,
                "group":active_directory.find_group,
                "computer":active_directory.find_computer
            }
            data = []
            if not props:
                props = ["cn"]
            asset = type_map.get(type)(asset)
            for member in asset.memberOf:
                obj = self.iterate_props(member,props)
                if obj:
                    data.append(obj)  
            return data            

        @should_we_run        
        def get_ad_groupmember(self,group="Domain Admins",props=None,**kwargs):
            data = []
            if not props:
                props=["cn","objectsid","userprincipalname","description"]
            search_group = active_directory.find_group(group)
            all_users = set()
            for group, groups, users in search_group.walk():
                all_users.update(users)
                
            for user in all_users:
                obj = self.iterate_props(user,props)
                if obj:
                    data.append(obj)
            return data

        @should_we_run        
        def get_neighbor(self,props=None,**kwargs):
            dataset = []
            targets = self.get_arp_table(limit=50)
            for target in targets:
                ip = target["addr"]
                asset = self.ip_to_hostname(ip)
                temp = {"asset":asset,"address":ip,"status":"up",
                    "host_name":self.hostname,"host_id":self.aid,"mac":target["mac"],
                    "type":target["type"]}
                dataset.append(temp)
            return dataset             
        
        @should_we_run        
        def get_scan(self,ports=[],props=None,**kwargs):
            dataset = []
            if not ports:
                ports = ['80', '23', '443', '21', '22', '25', '3389', '110', 
                '445', '139', '143', '53', '135', '3306', '8080', '1723', '111', 
                '995', '993', '5900', '1025', '587', '8888', '199', '1720', '465', 
                '548', '113', '81', '6001', '10000', '514', '5060', '179', '1026', 
                '2000', '8443', '8000', '32768', '554', '26', '1433', '49152', '2001', 
                '515', '8008', '49154', '1027', '5666', '646', '5000', '5631', '631', 
                '49153', '8081', '2049', '88', '79', '5800', '106', '2121', '1110', '49155', 
                '6000', '513', '990', '5357', '427', '49156', '543', '544', '5101', '144', 
                '7', '389', '8009', '3128', '444', '9999', '5009', '7070', '5190', '3000', 
                '5432', '1900', '3986', '13', '1029', '9', '5051', '6646', '49157', '1028', 
                '873', '1755', '2717', '4899', '9100', '119', '37', '1000', '3001', '5001', 
                '82', '10010', '1030', '9090', '2107', '1024', '2103', '6004', '1801', '5050', 
                '19', '8031', '1041', '255', '1056', '1049', '1065', '2967', '1048', '1053', 
                '1064', '1054', '3703', '17', '808', '3689', '1031', '1044', '1071', '5901', 
                '100', '9102', '8010', '2869', '1039', '4001', '9000', '5120', '2105', '636', 
                '1038', '2601', '1', '7000', '1066', '1069', '625', '311', '280', '254', '4000', 
                '1761', '5003', '2002', '2005', '1998', '1032', '1050', '6112', '3690', '1521', 
                '2161', '6002', '1080', '2401', '902', '4045', '7937', '787', '1058', '2383', 
                '32771', '1040', '1033', '1059', '50000', '5555', '10001', '1494', '593', '3', 
                '2301', '7938', '3268', '1022', '1234', '1074', '9001', '8002', '1036', '1035', 
                '1037', '464', '1935', '6666', '2003', '497', '6543', '1352', '24', '3269', '1111', 
                '407', '500', '20', '2006', '1034', '3260', '15000', '1218', '4444', '264', '33', 
                '2004', '1042', '42510', '3052', '999', '1023', '1068', '222', '7100', '888', '563', 
                '1717', '992', '32770', '2008', '32772', '7001', '8082', '2007', '5550', '5801', 
                '512', '1043', '2009', '7019', '50001', '2701', '1700', '4662', '2065', '2010', 
                '42', '2602', '3333', '161', '9535', '5100', '5002', '2604', '4002', '6059', '1047', 
                '8194', '8193', '8192', '9595', '9594', '9593', '16993', '16992', '6789', '5226', 
                '5225', '32769', '1052', '3283', '1062', '9415', '8701', '8652', '8651', '8089', 
                '65389', '65000', '64680', '64623', '55600', '55555', '52869', '35500', '33354', 
                '23502', '20828', '2702', '1311', '1060', '4443', '1051', '1055', '1067', '13782', 
                '5902', '366', '9050']
            targets = self.get_arp_table(limit=10)
            for target in targets:
                ip = target["addr"]
                asset = self.ip_to_hostname(ip)
                open_ports = self.tcp_scan(ip,ports=ports)
                for port in open_ports:
                    temp = {"asset":asset,"address":ip,"port":port,
                        "host_name":self.hostname,"host_id":self.aid,"mac":target["mac"]}
                    dataset.append(temp)
            return dataset        
        
        def ip_to_hostname(self,ip):
            try:
                host,alias,ip_alias = socket.gethostbyaddr(ip)
                return host
            except:
                return "unknown"
        
        def icmp_scan(self,ip):
            try:
                ping = subprocess.check_output(
                    ["ping", "-n", "1", ip],
                    timeout=1
                )
                if "unreachable" not in ping.decode():
                    return True
            except:
                pass
            return False

        def tcp_scan(self,ip,ports=[]):
            data = []
            if not isinstance(ports,list):
                ports = [ports]            
            socket.setdefaulttimeout(0.01)
            for port in ports:
                try:
                    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        
                    if not tcp.connect_ex((ip, int(port))):
                        data.append(port)
                    tcp.close()            
                except:
                    pass
            return data
        
        # May Get Rid of this...
        def get_pid(self,pname=None,**kwargs):
            if pname is None:
                raise Exception("pname (process name) is required")
            pname = pname.lower()
            data = []
            for proc in psutil.process_iter(attrs=['status', 'pid', 'cmdline', 'create_time', 'username', 'name']):
                try:
                    if pname in proc.info['name'].lower() or pname in proc.info['cmdline'] and proc.info['cmdline'][0]:
                        started = self.timestamp_to_readable(proc.info['create_time'])
                        proc.info['create_time'] = started
                        data.append(proc.info)
                except IndexError:
                    pass            
            return data
        
        def get_arp_table(self,limit=50):
            data = []
            try:
                with os.popen('arp -a') as f:
                    table = f.read()
                    for line in re.findall('([-.0-9]+)\s+([-0-9a-f]{17})\s+(\w+)',table)[:limit]:
                        addr,mac,type = line
                        try:
                            #we only want private, need better way to remove broadcast
                            #get network bits from primary interface and pass to ipaddress
                            if ipaddress.ip_address(str(addr)).is_private and "255" not in str(addr):
                                data.append({"addr":addr,"mac":mac,"type":type})
                        except ValueError:
                            pass #invalid ip
            except Exception as e:
                pass
            return data
        
        #-----------------------------------------------ALL HELPER FUNCTIONS and WRAPPERS-----------------------------------------------     
        def get_ip(self):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(('10.255.255.255', 1))
                IP = s.getsockname()[0]
            except Exception:
                IP = '127.0.0.1'
            finally:
                s.close()
            return IP
            
        def ad_walk(self,obj,flatten=False,**kwargs):
            '''
            Walk membership or memberof for a object
            flatten - if true,recursively walk a object and flatten the tree into single depth
                if false,only get relative relationsips for the object
            '''
            data = {"objectclass":obj.Class,"memberof":{"list":[]}}

            r_members = []    
            r_memberof = []
            
            def resolve(obj,memberof=False,members=False):
                if memberof:
                    for memberof in obj.memberOf:        
                        name = "{}.{}".format(memberof.cn,self.parse_domain_from_dn(memberof.distinguishedname)).lower()        
                        
                        if name not in r_memberof:            
                            r_memberof.append(name)
                            if hasattr(memberof,"memberOf"):
                                resolve(memberof,memberof=True)
                    return r_memberof

                elif members:
                    for member in obj.member:            
                        name = "{}.{}".format(member.cn,self.parse_domain_from_dn(member.distinguishedname)).lower()                                
                        if name not in r_members:  
                            r_members.append(name)
                            temp_data[member.Class]["list"].append(name)
                            if hasattr(member,"member"):
                                resolve(member,members=True) 
                    return temp_data           

            memberof_count = 0    
            if hasattr(obj,"memberOf"):
                for member in obj.memberOf:
                    name = "{}.{}".format(member.cn,self.parse_domain_from_dn(member.distinguishedname)).lower()        
                
                    data["memberof"]["list"].append(name)
                    if flatten:
                        resolved = resolve(member,memberof=True)
                        data["memberof"]["list"] = list(set(data["memberof"]["list"]+resolved)) #combine and dedup
                memberof_count = len(data["memberof"]["list"])  

            final_members = []
            member_count = 0
            if hasattr(obj,"member"):
                temp_data = {"computer":{"count":0,"list":[]},
                    "user":{"count":0,"list":[]},"group":{"count":0,"list":[]}}    
                for member in obj.member:  
                    name = "{}.{}".format(member.cn,self.parse_domain_from_dn(member.distinguishedname)).lower()
                
                    if member.Class in ("user","group","computer"):
                        member_count += 1
                        temp_data[member.Class]["count"] += 1            
                        temp_data[member.Class]["list"].append(name)
                        if flatten:
                            r = resolve(member,members=True)
                            for objclass,assets in r.items():
                                for member in assets:
                                    if member not in final_members:
                                        final_members.append(member)
                                        member_count += 1
                                        temp_data[objclass]["count"] += 1                                        
                                        temp_data[objclass]["list"].append(member)
                data["members"] = temp_data
                data["members_count"] = member_count
            data["memberof_count"] = memberof_count        
            return data  
        
        def parse_domain_from_dn(self,dn):
            base_dn = ""
            try:
                for rdn in to_dn(dn,decompose=True):
                    base,value = rdn
                    if base.lower() == "dc":
                        base_dn += ".{}".format(value)
                if base_dn:
                    return base_dn[1:]
            except:
                pass
            return None
    
        def generate_random_password(self,length=20):
            alphabet = "abcdefghijkmnpqrstuvwxyz23456789ABCDEFGHJKMNPQRSTUVWXYZ"
            pw_length = length
            password = "a?2A"
            for i in range(pw_length):
                next_index = random.randrange(len(alphabet))
                password = password + alphabet[next_index]
            return password[:-4]

        def get_name_for_sid(self,sid,server=None):
            try:
                sid = win32security.GetBinarySid(sid)
                data = win32security.LookupAccountSid(server,sid)
                if data:
                    return data[0]
            except Exception as e:
                pass
            return None

        def get_user_info(self,username, level, server="localhost"):
            try:
                return win32net.NetUserGetInfo(server, username, level)
            except Exception as e:
                return None    

        def get_user_info_ex_bak(self, sid, level, server=None):
            if isinstance(sid,str):
                sid = win32security.ConvertStringSidToSid(sid)
            user = win32security.LookupAccountSid(server,sid)
            if user:
                try:
                    return win32net.NetUserGetInfo(server, user[0], level)
                except Exception as e:
                    return None
            return None    

        def get_user_info_ex(self,sid, level, server=None):
            try:
                if isinstance(sid,str):
                    sid = win32security.ConvertStringSidToSid(sid)
                if server == "localhost":
                    user = win32security.LookupAccountSid(win32api.GetComputerName(),sid) # server can not be LocalHost
                else:                    
                    user = win32security.LookupAccountSid(server,sid)

                if user:
                    user_info = win32net.NetUserGetInfo(server, user[0], level)
                    return True,user_info          
            except Exception as e:             
                return False,str(e)
            return False,"Unable to get user information"            
                
        def rotate_user_password(self, username, sid, server, rotate_method, old_password=None, length=20, local_account=True, 
            password_expires=False, disable=False, logon_workstations=None):  
            
            data = {"username":username,"sid":sid,"success":False,"domain":server,"rotate_method":rotate_method,"local_account":local_account}            
            result,user_info = self.get_user_info_ex(sid, 4,server=server)             
                        
            if result:
                name = user_info["name"]
                new_password = self.generate_random_password(length=length) 
                try:
                    # set user attributes
                    if password_expires:
                        user_info["flags"] &= ~win32netcon.UF_DONT_EXPIRE_PASSWD
                    else:
                        user_info["flags"] |= win32netcon.UF_DONT_EXPIRE_PASSWD
                    if disable:
                        user_info["flags"] |= win32netcon.UF_ACCOUNTDISABLE
                    else:
                        user_info["flags"] &= ~win32netcon.UF_ACCOUNTDISABLE               

                    # change or set the password
                    if rotate_method == "change":
                        if not old_password:
                            data["error"] = "4000 - Missing old password during password change"
                            return data
                            
                        if user_info.get("workstations"): # must clear this value if changing password or we get 2240 error
                            user_info["workstations"] = ''
                            win32net.NetUserSetInfo(server, name, 2,user_info)                

                        if logon_workstations:
                            user_info["workstations"] = logon_workstations 
                            
                        win32net.NetUserChangePassword(server,name,old_password,new_password)
                        win32net.NetUserSetInfo(server, name, 2, user_info)                
                    else:
                        if logon_workstations:
                            user_info["workstations"] = logon_workstations                    
                        user_info["password"] = new_password                            
                        win32net.NetUserSetInfo(server, name, 2, user_info)
                        
                    data["password"] = new_password  
                    data["success"] = True
                    data["disable"] = disable
                    data["password_expires"] = password_expires
                    data["logon_workstations"] = logon_workstations

                except Exception as e:
                    error = str(e)
                    if "2245" in error:
                        message = "2245 - Password does not meet the password policy requirements"
                    elif "2240" in error:
                        message = "2240 - The user is not allowed to log on from this workstation"
                    elif "86" in error:
                        message = "86 - Password does not match the old password"                
                    else:
                        message = "8000 - General error. {}".format(error)                        
                    data["error"] = message 
            else:
                data["error"] = user_info                     
            return data                              
        
        def find_account_by_name_locally(self,name):
            try:
                if not self.is_dc:
                    account = win32net.NetUserGetInfo("localhost",name,3)            
                    return account
            except:
                pass
            return None
            
        def find_account_by_name_globally(self,name):
            try:
                if self.domain_joined:
                    account = win32net.NetUserGetInfo(self.domain,name,3)
                    return account
            except:            
                pass  
            return None

        def get_account_info(self,name,local_lookup=True,domain_lookup=True):
            data = {}           
            found = False
            # local lookup
            if local_lookup:
                account_data = self.find_account_by_name_locally(name)
                if account_data:
                    local = True
                    found = True
            # domain lookup
            if domain_lookup and not found:
                account_data = self.find_account_by_name_globally(name)
                if account_data:
                    local = False
                    found = True
            if self.is_dc:
                local = False  
                
            # format the data
            if found:
                today = datetime.today()
                data_keys = ["name","password_age","priv","comment","flags","script_path",
                    "last_logon","last_logoff","num_logons","acct_expires",
                    "bad_pw_count","primary_group_id","user_id","password_expired"]     
                try: 
                    temp = {"local_account":local}
                    for key,value in account_data.items():
                        key = key.lower()
                        if key in data_keys:
                            if key in ("acct_expires","last_logon","last_logoff"):
                                value = datetime.fromtimestamp(value).strftime("%Y-%m-%d")
                            elif key == "password_age":
                                days = round(((value/60)/60)/24)
                                last_password_change = (today - timedelta(days=days)).strftime("%Y-%m-%d")
                                temp["last_password_change"] = last_password_change
                                value = days                                                             
                            elif key == "name":
                                key = "username"
                            elif key == "flags":
                                temp["useraccountcontrol"] = UserAccountControl(str(value)).humanReadeable()                                                            
                            temp[key] = value
                    data = temp
                except:
                    pass
            return data
   
        def lookup_account(self,name,server=None,convert_sid_to_string=True,collect_info=False):
            data = {}    
            sid_obj,domain,atype = win32security.LookupAccountName(server,name)
            if convert_sid_to_string:
                 sid = win32security.ConvertSidToStringSid(sid_obj)
            data["sid"] = sid
            data["domain"] = domain
            data["account_type"] = self.get_accounttype(atype)
            
            if collect_info:
                extra_data = self.get_account_info(name)
                if extra_data:
                    data = {**data,**extra_data}
            return data

        def to_tabulate(self,data,vertical=None):
                '''
                :data=[{"header1":"value1"}]
                '''
                if not isinstance(data,(list,dict)):
                    return data
                data_list = []
                headers = []    
                if isinstance(data,dict):
                    data = [data]
                if vertical:
                    for each in data:
                        headers = ["Key","Value"]            
                        for k,v in each.items():                    
                            data_list.append([str(k),str(v)])
                        if each:
                            data_list.append(["--------------------------------------------","--------------------------------------------"])
                    return tabulate(data_list,headers=headers)
                else:
                    return tabulate(data,headers="keys") 
        
        def parse_args(self,argv):
            type_map = {
                "vertical":float,
                "console":float,
                "force":float,
                "hours":float,
                "limit":float,
            }           
            parsed = {}
            try:
                for item in argv.split(";"):
                    k,v = item.strip().split("=")
                    k = k.strip()
                    v = v.strip()
                    if "{" in v:
                        if not isinstance(v,dict):
                            v=ast.literal_eval(v)                    
                    if "," in v or k in ("inc","exc","eventid"):
                        temp = v.split(",")
                        new_list = []
                        for item in temp:
                            new_list.append(item.strip())
                        v = new_list
                    parsed[k] = v
                for k,v in parsed.items(): #// convert to int
                    if k in type_map:
                        parsed[k] = type_map.get(k)(v)
                return parsed
            except:
                return None  
                
        def str2bool(self,v):
            return str(v).lower() in ("true")
        
        def ctime_to_date(self,value):
            try:
                return time.ctime(value) 
            except:
                return value
        
        def get_accounttype(self,atype):
            atype_map = {
                "1":"user",
                "2":"group",
                "3":"domain",
                "4":"alias",
                "5":"wellknowngroup",
                "6":"deletedaccount",
                "7":"invalid",
                "8":"unknown",
                "9":"computer"
            }
            try:
                return atype_map.get(str(atype),"unknown")
            except:
                return "unknown"                  
                           
    
        def get_hash(self,file,only_hash=False,**kwargs):
            data = []
            BUF_SIZE = 65536
            if os.path.isfile(file):
                sha1 = hashlib.sha1()
                with open(file, 'rb') as f:
                    while True:
                        d = f.read(BUF_SIZE)
                        if not d:
                            break
                        sha1.update(d) 
                if only_hash:
                    return sha1.hexdigest()
                data.append({"flavor":"sha1","filename":file,"hash":sha1.hexdigest()})
            return data 
        
        def resolve_ip(self,ip,**kwargs):
            try:
                data = socket.gethostbyaddr(ip)
                host = data[0]
                return host
            except:
                return None
        
        def convert_guid(self,guid,as_object=False):
            value = pywintypes.IID(guid,True)
            if as_object:
                return value     
            return(str(value))

        def convert_sid(self,sid,as_object=False):
            value = pywintypes.SID(sid)
            if as_object:
                return value       
            return str(value).split(":")[1]

        def iterate_props(self,object,props):
            #print(active_directory._PROPERTY_MAP["badPasswordTime"](value))
            data = {}
            if not isinstance(props, list):
                props = [props]

            latest = None #variable for lastlogon and lastlogontimestamp
            for attr in object.properties:
                try:
                    if attr.lower() in props and hasattr(object,attr.lower()):
                        if attr.lower() in ("objectguid","msexchmailboxguid"):
                            to_bytes = getattr(object,attr).tobytes()
                            value = self.convert_guid(to_bytes)
                        elif attr.lower() in ("objectsid"):
                            value = win32security.ConvertSidToStringSid(getattr(object,attr))       
                        elif attr.lower() in ("lastlogontimestamp","lastlogon"):
                            if not latest: 
                                latest = getattr(object,attr)
                            if getattr(object,attr) > latest:
                                latest = getattr(object,attr)                     
                        else:
                            try:
                                value = getattr(object,attr)
                            except:
                                value = None
                        if value:
                            if not isinstance(value,(int,float,list)):
                                value = str(value) 
                            attr=attr.replace("-","").lower()
                            data[attr] = value
                    if latest:
                        data["lastlogon"] = str(latest)
                except:
                    pass
            data["host_name"] = self.hostname 
            data["host_id"] = self.aid            
            return data
            
        def timestamp_to_readable(self,time_str):
            try:
                return datetime.fromtimestamp(time_str).strftime("%Y-%m-%d %H:%M:%S")
            except:
                return time_str
    
        def filter_op(self,data,filter=[],case_insen=True): 
            op_map = {
                "eq":operator.eq,
                "ne":operator.ne
            }  
            if not filter:
                return data
            if isinstance(data,dict):
                for filt in filter:
                    k,op,v = filt
                    if case_insen:
                        k = k.lower()
                        if isinstance(v,str):
                            v = v.lower()
                    if not op_map[op](data[k],v):
                        return None
                return data
                                
        def filter_fields(self,data,filter=[],exc=[],inc=[],case_insen=True):
            '''
            :Description - Basic JSON filtering. Ingests data dictionary, filters (ne,eq), filters fields, and returns result
            :Usage - filter_fields({"f1":"data","f2":"test"},filter=[("f2","eq","test")],exc_fields=["f1"])
            :data - [{},{}]
            :filter - [("f2","eq","test")]
            :exc / inc - ["f1"]
            '''            
            inc = [x.lower() for x in inc if inc]
            exc = [x.lower() for x in exc if exc]
            dataset = [] 
            
            if not isinstance(data,(dict,list)):
                return data
            
            if isinstance(data,dict):
                data = [data]
                
            for record in data:
                temp_dict = {}
                for key,value in record.items():
                    if case_insen:                
                        key = key.lower()
                        if isinstance(value,str):                        
                            value = value.lower()
                    if key not in exc:                    
                        if not inc:
                            temp_dict[key] = value                        
                        elif key in inc:
                            temp_dict[key] = value
                dataset.append(temp_dict)
            return dataset     
            
        def kill_process(self,procname):
            for proc in psutil.process_iter():
                if proc.name() == procname:
                    proc.kill()
                    return True
            return None
        
        def create_folders(self, baseFolder=None,subfolders=[]):
            '''
            .description: Recursively create folders in working directory (mkdir -p)
            '''  
            if baseFolder is None:
                baseFolder = self.working_dir
            for folder in subfolders:
                full_folder_path = os.path.join(baseFolder,folder)
                if not os.path.exists(full_folder_path):
                    try:
                        os.makedirs(full_folder_path)
                        self.event_logger(message="Successfully created folder: %s" % folder,log_type="info")                        
                    except OSError as exc:
                        if exc.errno == errno.EEXIST and os.path.isdir(full_folder_path):
                            pass
                        else:
                            raise
            return True            

        def locate_file(self, search_dir, prefix, suffix):
            '''
            .description: Given a directory, return the full path of a file
            .prefix - Start of a file
            .suffix - file ending
            '''
            prefix = prefix.lower()
            suffix = suffix.lower()
            for file in os.listdir(search_dir):
                file = file.lower()
                if file.startswith(prefix) and file.endswith(suffix): #// Search for prefix/suffix of the file
                    abs_filepath = os.path.join(search_dir,file)
                    return abs_filepath
            return None 

        def unzip_file(self, zip_src_path, zip_dest_path):
            '''
            .description: Unzip a file and save it to a destination
            '''
            zip_ref = zipfile.ZipFile(zip_src_path,"r")
            zip_ref.extractall(zip_dest_path)
            zip_ref.close()
            return zip_dest_path            

        def get_fileproperties(self,fname):
            '''
            Read all properties of the given file return them as a dictionary.
            '''
            propNames = ('Comments', 'InternalName', 'ProductName',
                'CompanyName', 'LegalCopyright', 'ProductVersion',
                'FileDescription', 'LegalTrademarks', 'PrivateBuild',
                'FileVersion', 'OriginalFilename', 'SpecialBuild')

            props = {'FixedFileInfo': None, 'StringFileInfo': None, 'FileVersion': None}

            try:
                # backslash as parm returns dictionary of numeric info corresponding to VS_FIXEDFILEINFO struc
                fixedInfo = win32api.GetFileVersionInfo(fname, '\\')
                props['FixedFileInfo'] = fixedInfo
                props['FileVersion'] = "%d.%d.%d.%d" % (fixedInfo.get('FileVersionMS') / 65536,
                        fixedInfo.get('FileVersionMS') % 65536, fixedInfo.get('FileVersionLS') / 65536,
                        fixedInfo.get('FileVersionLS') % 65536)

                # \VarFileInfo\Translation returns list of available (language, codepage)
                # pairs that can be used to retreive string info. We are using only the first pair.
                lang, codepage = win32api.GetFileVersionInfo(fname, '\\VarFileInfo\\Translation')[0]

                # any other must be of the form \StringfileInfo\%04X%04X\parm_name, middle
                # two are language/codepage pair returned from above

                strInfo = {}
                for propName in propNames:
                    strInfoPath = u'\\StringFileInfo\\%04X%04X\\%s' % (lang, codepage, propName)
                    strInfo[propName] = win32api.GetFileVersionInfo(fname, strInfoPath)

                props['StringFileInfo'] = strInfo
            except:
                pass
            return props

        def enum_directory(self,start_dir):
            '''Given a directory, recursively grab and return abs path of all files'''
            paths = []
            def listdir(d):
                if not os.path.isdir(d):
                    paths.append(d)
                else:
                    try:
                        for item in os.listdir(d):
                            listdir((os.path.join(d,item)) if d != "\\" else os.path.join("\\",item))
                    except:
                        pass # Permission denied
            listdir(start_dir)
            return paths

        def get_file_details(self,abs_file):
            data = {}
            date_format = "%Y-%m-%d %H:%M:%S"
            if os.path.isfile(abs_file):
                data["access"] = str(datetime.fromtimestamp(os.path.getatime(abs_file)).strftime(date_format)) 
                data["modify"] = str(datetime.fromtimestamp(os.path.getmtime(abs_file)).strftime(date_format))                
                data["create"] = str(datetime.fromtimestamp(os.path.getctime(abs_file)).strftime(date_format))
                try:
                    data["size"] = os.path.getsize(abs_file)
                except WindowsError:
                    size = "-"
            return data
    
        def get_dir(self,path):
            headers = ["Type","Filename","Size","Access","Modify","Create"] 
            data = []
            if not os.path.isabs(path):
                path = os.path.abspath(path)       
            for each in os.listdir(path):
                abs_file = os.path.join(path,each)
                if os.path.isdir(abs_file):
                    ftype="Dir"
                else:
                    ftype="File"
                access = str(datetime.fromtimestamp(os.path.getatime(abs_file)).strftime("%c")) 
                modify = str(datetime.fromtimestamp(os.path.getmtime(abs_file)).strftime("%c"))                
                create = str(datetime.fromtimestamp(os.path.getctime(abs_file)).strftime("%c"))
                try:
                    size = os.path.getsize(abs_file)
                except WindowsError:
                    size = "-"
                data.append([ftype,each,size,access,modify,create])
            return tabulate(data,headers=headers)              

        def log_to_debug_log(self,message,log_type="warning"):
            now = str(datetime.utcnow())
            if os.path.exists(self.log_dir):
                with open(self.log_file,"a") as f:
                    f.write("[]-{}: {}".format(now,log_type.upper(),message))
                return True
            return None

        def event_logger(self, message=str(), log_type="warning", eventid=1000, send_to_svcmgr=True, send_to_file=False, post_to_server=None):
            if not isinstance(eventid, int):
                eventid=1000
            if send_to_svcmgr:
                log = getattr(servicemanager,"EVENTLOG_WARNING_TYPE")
                if log_type in ("error"):
                    log = getattr(servicemanager,"EVENTLOG_ERROR_TYPE")
                elif log_type in ("info"):
                    log = getattr(servicemanager,"EVENTLOG_INFORMATION_TYPE")
                #// Send to event viewers
                servicemanager.LogMsg(log,eventid,("[{} - {}]: {}".format(log_type.upper(),self.version,message),""))
            
            #// Send to file
            if send_to_file:
                self.log_to_debug_log(message,log_type=log_type)
            
            #if post_to_server is True:
                #// Send to server error log
                #self.post_data(message=message)
            return True
            
        class CustomCode(Exception):
            '''
            :Description - Custom error codes
            '''
            def __init__(self,code):
                self.code = code        
            def __str__(self):
                return repr(self.code)          
        
        
class GetFileAcl():
    '''Collect ACLs for files (on disk files, file shares, gpos, etc..)'''
    def __init__(self,path):
        self.path = path
        
        self.ACE_TYPE = self.build_flags_map('ACCESS_ALLOWED_ACE_TYPE', 'ACCESS_DENIED_ACE_TYPE')

        self.ACCESS_MASK = self.build_flags_map(
            'GENERIC_WRITE', 'GENERIC_ALL', 'GENERIC_EXECUTE', 'GENERIC_READ',
            'WRITE_OWNER', 'DELETE', 'READ_CONTROL', 'SYNCHRONIZE', 'WRITE_DAC',
            'ACCESS_SYSTEM_SECURITY')

        self.ACCESS_MASK_FILES = self.build_flags_map(
                'FILE_ADD_FILE', 'FILE_READ_DATA', 'FILE_LIST_DIRECTORY',
                'FILE_WRITE_DATA', 'FILE_ADD_FILE', 'FILE_APPEND_DATA',
                'FILE_ADD_SUBDIRECTORY', 'FILE_CREATE_PIPE_INSTANCE', 'FILE_READ_EA',
                'FILE_WRITE_EA', 'FILE_EXECUTE', 'FILE_TRAVERSE', 'FILE_DELETE_CHILD',
                'FILE_READ_ATTRIBUTES', 'FILE_WRITE_ATTRIBUTES', 'FILE_ALL_ACCESS',
                'FILE_GENERIC_READ', 'FILE_GENERIC_WRITE', 'FILE_GENERIC_EXECUTE',
                mod=ntsecuritycon,
            )

        self.ACE_FLAGS = self.build_flags_map(
            'CONTAINER_INHERIT_ACE', 'INHERITED_ACE', 'FAILED_ACCESS_ACE_FLAG',
            'INHERIT_ONLY_ACE', 'OBJECT_INHERIT_ACE',
            mod=win32security)  
        try:
            dsdc = win32security.DsGetDcName() 
            self.domain = dsdc.get("DomainName")            
        except:
            self.domain = None
        
    def show_acls(self):
        data = {"path":self.path,"name":os.path.basename(self.path),"aces":[],"user_ace":0,"group_ace":0,"computer_ace":0}

        desc = win32security.GetNamedSecurityInfo(
                self.path,
                win32security.SE_FILE_OBJECT,
                win32security.DACL_SECURITY_INFORMATION)    
        dacl = desc.GetSecurityDescriptorDacl()
        acecount = dacl.GetAceCount()    
        data["acecount"] = acecount
        
        for i in range(0, dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            (ace_type, ace_flags), ace_mask, ace_sid = ace
            sid = win32security.ConvertSidToStringSid(ace_sid)
            try:
                username, domain, atype = win32security.LookupAccountSid(self.domain,ace_sid)
                if atype == 1:
                    data["user_ace"] += 1
                elif atype == 2:
                    data["group_ace"] += 1
                elif atype == 9:
                    data["computer_ace"] += 1
            except:
                username = "unknown"
                domain = "unknown"
                atype = "unknown"

            data["aces"].append({
                "username": username,
                "domain": domain,
                "account_type":self.get_accounttype(atype),
                "sid": sid,
                "ace_type":self.ACE_TYPE[ace_type],
                "ace_flags":self.display_flags(self.ACE_FLAGS, ace_flags),
                "ace_mask":self.display_flags(self.ACCESS_MASK_FILES, ace_mask),
            })
        return data   

    def build_flags_map(self,*attrs, **kw):
        mod = kw.get('mod', win32con)

        r = {}
        for attr in attrs:
            value = getattr(mod, attr)
            r[value] = attr
        return r
        
    def display_flags(self,map, value):
        r = []
        for flag, name in map.items():
            if flag & value:
                r.append(name)
                value = value - flag
        #if value != 0:
            # We didn't specified all the flags in the mapping
            #r.append('(flags left 0x%x)' % value)
        return r 

    def get_accounttype(self,atype):
        atype_map = {
            "1":"user",
            "2":"group",
            "3":"domain",
            "4":"alias",
            "5":"wellknowngroup",
            "6":"deletedaccount",
            "7":"invalid",
            "8":"unknown",
            "9":"computer"
        }
        try:
            return atype_map.get(str(atype),"unknown")
        except:
            return "unknown"         

class UserAccountControl():
    '''#print(UserAccountControl("66147").humanReadeable())'''
    def __init__(self,value=None):
        self.value = value

        self.acControl = {
            "1": "SCRIPT",
            "2": "ACCOUNTDISABLE",
            "8": "HOMEDIR_REQUIRED",
            "16": "LOCKOUT",
            "32": "PASSWD_NOTREQD",
            "64": "PASSWD_CANT_CHANGE",
            "128": "ENCRYPTED_TEXT_PWD_ALLOWED",
            "256": "TEMP_DUPLICATE_ACCOUNT",
            "512": "NORMAL_ACCOUNT",
            "2048": "INTERDOMAIN_TRUST_ACCOUNT",
            "4096": "WORKSTATION_TRUST_ACCOUNT",
            "8192": "SERVER_TRUST_ACCOUNT",
            "65536": "DONT_EXPIRE_PASSWORD",
            "131072": "MNS_LOGON_ACCOUNT",
            "262144": "SMARTCARD_REQUIRED",
            "524288": "TRUSTED_FOR_DELEGATION",
            "1048576": "NOT_DELEGATED",
            "2097152": "USE_DES_KEY_ONLY",
            "4194304": "DONT_REQ_PREAUTH",
            "8388608": "PASSWORD_EXPIRED",
            "16777216": "TRUSTED_TO_AUTH_FOR_DELEGATION"
        }        
        
    def humanReadeable(self):
        if self.value == None:
            return str(self.value)
        binary = bin(int(self.value))[2:][::-1]
        values = []
        for bit in range(0,len(binary)):
            if binary[bit] == '1':
                decimal = int(binary[bit]+'0'*bit,2)
                try:
                    value = self.acControl.get(str(decimal))
                    values.append(value)
                except:
                    #values.append("UNKNOWN")
                    pass
        return values  

    def reversible_encryption(self):
        return "ENCRYPTED_TEXT_PWD_ALLOWED" in self.humanReadeable()
        
    def is_disabled(self):
        return "ACCOUNTDISABLE" in self.humanReadeable()
    
    def is_lockedout(self):
        return "LOCKOUT" in self.humanReadeable()
    
    def password_required(self):
        return "PASSWD_NOTREQD" not in self.humanReadeable()
    
    def non_expire_password(self):
        return "DONT_EXPIRE_PASSWORD" in self.humanReadeable()
    
    def require_preauth(self):
        return "DONT_REQ_PREAUTH" not in self.humanReadeable()
    
    def password_expired(self):
        return "PASSWORD_EXPIRED" in self.humanReadeable()
    
    def delegation_enabled(self):
        return "TRUSTED_FOR_DELEGATION" or "TRUSTED_TO_AUTH_FOR_DELEGATION" in self.humanReadeable()
        
class Registry_Read():
    '''
    #obj = Registry_Read(HKEY_LOCAL_MACHINE)
    
    #------Get all data
    #keypath = r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\'
    #obj.get_key_values(keypath)

    #------Get keys
    #keypath = r'System\\CurrentControlSet\\Services\\'
    #print obj.get_subkeys(keypath)

    #------Get values
    #keypath = r'System\\CurrentControlSet\\Services\\test9'
    #print obj.get_values(keypath)
    
    #------Create Registry Attribute
    #keypath = r'System\\CurrentControlSet\\Services\\test9'
    obj.createRegistryParameter(keypath,"key","value")
    '''
    def __init__(self, const):
        HIVE = {
            "hklm":HKEY_LOCAL_MACHINE,
            "hkcu":HKEY_CURRENT_USER,
            "hku":HKEY_USERS
        }
        STR_HIVE = {
            "hklm":"HKEY_LOCAL_MACHINE",
            "hkcu":"HKEY_CURRENT_USER",
            "hku":"HKEY_USERS"
        }
        self.const = HIVE[const]
        self.strconst = STR_HIVE[const]

    def key_exist(self,keypath):
        try:
            ob = OpenKey(self.const, keypath, 0, KEY_READ)
            return True
        except:
            return None
        
    def list_contents(self,keypath):
        keypath = keypath.lstrip("\\")    
        keypath = keypath.rstrip("\\") 
        temp = {}
        if self.key_exist(keypath):
            attrib = self.get_values(keypath)
            if not attrib:
                for index,key in enumerate(self.get_subkeys(keypath)):
                    temp["key"+str(index)] = key
                return temp
            return attrib
        # try to get the value
        relpath = os.path.dirname(keypath)
        value = os.path.basename(keypath)
        if self.key_exist(relpath):
            return(self.get_values(relpath).get(value.lower()))
        return None        

    def get_subkeys(self, keypath):
        keys = None
        try:
            ob = OpenKey(self.const, keypath, 0, KEY_READ)
            keys = self.get_subattribs('key', ob)
        except Exception as e:
            pass
            #print("Exception occured :- {}, key path :- {}".format(e, keypath))
        return keys

    def get_values(self, keypath):
        dict = {}
        try:
            with OpenKey(self.const, keypath, 0, KEY_READ) as subkey:
                v = self.get_subattribs('values',subkey)
                for each in v:
                    dict[each[0]] = str(each[1])
        except Exception as e:
            pass
            #print("Exception occured :- {}, key path :- {}".format(e, keypath))
        return dict

    def get_subattribs(self, attrib_name, ob):
        count = 0
        attrib = []        
        while True:
            try:
                subattribs = EnumKey(ob, count) if attrib_name is 'key' else EnumValue(ob, count)
                attrib.append(subattribs)
                count+=1
            except WindowsError as e:
                break
        return attrib
        
    def get_all_values(self,keypath):
        full_list = []
        for keyname in self.get_subkeys(keypath):
            sub_values = self.get_values(os.path.join(keypath,keyname))
            temp = {}
            for attr,value in sub_values.items():
                temp[attr] = value
            if temp:
                temp["keyname"] = keyname
                full_list.append(temp)        
        return full_list
         
    def createRegistryParameter(self,keypath,argname,argvalue):
        newkey=win32api.RegOpenKeyEx(getattr(win32con,self.strconst), keypath,0,win32con.KEY_ALL_ACCESS)
        try:
            datatype = win32con.REG_SZ
            if isinstance(argvalue,(int,float)):
                datatype = win32con.REG_DWORD
            win32api.RegSetValueEx(newkey, argname, 0, datatype, argvalue)
        finally:
            newkey.Close()             

# Domain Helper Functions
def is_dc():
    try:
        if win32net.NetGroupGetInfo("localhost","Domain Controllers",0):
            return True       
    except:
        pass # group doesnt exist, not a DC  
    return False
        
def is_domain_joined():
    try:
        if win32net.NetGetJoinInformation()[1] == 3: # check if domain joined    
            return True
    except:
        pass
    return False

def get_domain_info():
    data = {"domain":"WORKGROUP","domaincontrollername":None,"domaincontrolleraddress":None,"forest":None}
    try:
        if is_domain_joined(): # if we are domain joined
            dsdc = win32security.DsGetDcName() 
            if dsdc.get("DomainName"):
                data["domain"] = dsdc.get("DomainName")
                
            if dsdc.get("DomainControllerName").replace("\\",""):
                data["domaincontrollername"] = dsdc.get("DomainControllerName")
                
            if dsdc.get("DomainControllerAddress").replace("\\",""):
                data["domaincontrolleraddress"] = dsdc.get("DomainControllerAddress")
                
            if dsdc.get("DnsForestName"):
                data["forest"] = dsdc.get("DnsForestName")
    except:
        pass
    return data
                    
if __name__ == '__main__':
    #// Called by service manager
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(AppServerSvc)
        servicemanager.StartServiceCtrlDispatcher()
    #// Command Line
    else:
        action = sys.argv[1]
        if action in ("install"):
            sys.argv=[sys.argv[0],"--startup=auto","install"]
            win32serviceutil.HandleCommandLine(AppServerSvc)
        elif action in  ("remove","restart","start","stop","debug","update"):
            win32serviceutil.HandleCommandLine(AppServerSvc)
