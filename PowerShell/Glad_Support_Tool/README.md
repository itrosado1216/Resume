GladTrace tool 

Description: 
The tool automates the way Gladinet support engineers collect server troubleshooting information from Gladinet's customers using Sysinternals Debug Viewer used by the development team to resolve software bugs. 
-It leverages Windows Form for the UI. 
-Handles environments where user signed in to Windows 10 machine is not Local administrator. (An elevated sesssion of Debug View is started from non-elevated session). 


The tool accomplishes all of the following;
1. Determines which platform (server client/windows client/server agent) and the version the system is running. 
-This ensured engineers always had the version of the product / and script execution logic. 

2. Downloads Debug View zip file from the SysInternal site, extracts it and configures it to use the flags needed for trace collection. 
-Engineer no longer eneded to manually naviagate to the SysInternal site to download the utility, then manually configured it as per Development requirement. 

3. If the script was running on the CentreStack server (IIS), it handled all of the entries needed to be made to the web.config file to enable tracing on the server. 

3. Grants the engineer the option to take screenshots while the script is executing and the engineer is reproducing the bug. 
This addressed the issue of engineers sometimes leaving out screenshots that aided the development team in understanding the bug. 

4. Gathered logs from all directories / Db files and ultimately zips and packages all tracing / troubleshooting information gathered from customers environment. 

5. Downloads corresponding version/platform symbol files to run WinDBG from our enviroment. 

6. Downloads WinDBB

7. Uploads the collected trace package to an Azure storage account via a SAS token. 
