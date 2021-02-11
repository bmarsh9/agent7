## Build  
pywin32  
requests  
psutil  
tabulate  
wmi  
active_directory  
    - This file needs to be edited: C:\full_path\adsi\__init__.py  
    - Change  
        - from adsi import *  
        - from .adsi import *  
        
pywintypes  

# build exe  
pyinstaller --hiddenimport win32timezone --hiddenimport wmi --onefile agent7.py  

# run innosetup to wrap the program  
    - edit version,server,sitekey and group (otherwise use command line during install)

# install agent (specify flags or build it into InnoSetup)  
`.\agent7_installer.exe /verysilent /server=ip /key=sitekey /group=dc-server /verifytls=yes`  
