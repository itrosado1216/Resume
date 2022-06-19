<#
.Description

Automates collection of Gladinet trace collection for Cloud Server, Windows Client and Server Agent.
.EXAMPLE
PS> .\GladTraceGUI-Main.ps1 
.NOTES

  Author  : Elvis Rosado
  Version : 2.2
  Purpose : Facilites the collection of troubleshooting logs related to Gladinet Products. 
  #Adding version release notes starting in version 2.2
  #2.2 changes: Symbol zip files now extract after they are downloaded
  #2.2: Logic has been modified to work on new server agent version that uses GServiceMain/Also downloads Corresponding Server symbol files for WinDBG.
  #2.3: zip Symbol file for WinClient now extracts after downloaded
#>

#Hides the PowerShell shell Window from the background.
#---Start
$hidden = '[DllImport("user32.dll")] public static extern bool ShowWindow(int handle, int state);'
add-type -name win -member $hidden -namespace native
[native.win]::ShowWindow(([System.Diagnostics.Process]::GetCurrentProcess() | Get-Process).MainWindowHandle, 0)
#---end

Function GladTraceToolUI {

    #Replace $Null with a SAS token
    $Script:SasToken = "sp=c&st=2021-10-13T18:56:43Z&se=2021-10-15T02:56:43Z&spr=https&sv=2020-08-04&sr=c&sig=1kf%2F%2F3Iq74X7DAw8Tij%2B53GeAaH0HsfWqW%2FYb1H6scs%3D"
    Add-Type -AssemblyName System.Windows.Forms, PresentationCore, PresentationFramework
    [System.Windows.Forms.Application]::EnableVisualStyles()
    If (-Not(Test-Path -Path "$Env:USERPROFILE\Downloads\GladinetTraceCollect")) {

        New-Item -Path "$Env:USERPROFILE\Downloads" -Name 'GladinetTraceCollect' -ItemType 'Directory' -Force | Out-Null
    }

    #Gladtrace is the main function called by the GladTrace GUI.
    Function GladTrace {

        [Cmdletbinding(DefaultParameterSetName = 'Collect')]
        param(

            [Parameter(ParameterSetName = 'Collect',
                Position = 0)]
            [Switch]$Collect,

            [Parameter(ParameterSetName = 'Export',
                Position = 0)]
            [Switch]$Pack,

            [Parameter(ParameterSetName = 'Export',
                Position = 1)]
            [Switch]$FileSysDB,

            [Parameter(ParameterSetName = 'Collect',
                Position = 1)]
            [Switch]$StepsRecorder,

            [Parameter(ParameterSetName = 'WinDBG',
                Position = 0)]
            [Switch]$WindbgInstall,

            [Parameter(ParameterSetName = 'WinDBG',
                Position = 0)]
            [Switch]$WindbgUninstall,

            [Switch]$DownloadpdbFiles, 

            [ValidateNotNullOrEmpty()]
            $LogCount = 5
        )

        Begin {

            #Requires -Version 4
            $Script:currentDate = (get-date).tostring("MM_dd_yyyy-hh_mm_s") 
            $Script:OutPath = "$Env:USERPROFILE\Downloads\GladinetTraceCollect"
            If (-Not(Test-Path -Path "$Env:USERPROFILE\Downloads\GladinetTraceCollect")) {

                New-Item -Path "$Env:USERPROFILE\Downloads" -Name 'GladinetTraceCollect' -ItemType 'Directory' -Force | Out-Null
            }
        }

        Process {

            If ($FileSysDB) {

                $Script:Version = Get-GladVersion -FileSysDB
            }

            Else {

                $Script:Version = Get-GladVersion
            }

            If ($Version.Productname -eq 'WindowsClient' -or $Version.Productname -eq 'CloudServer' -or $Version.Productname -eq 'ServerAgent') {

                If ($Collect) {

                    If ($StepsRecorder) {

                        $recCount = (Get-ChildItem -Path "$Env:USERPROFILE\Downloads\GladinetTraceCollect" | 
                            Where-Object { $_.Name -match 'Screenrecording' }).count

                        Enable-StepsRecorder -Start -OutPath "$Env:USERPROFILE\Downloads\GladinetTraceCollect\Screenrecording$recCount.zip"
                    }

                    If ($Version.ProductName -eq 'ServerAgent') {

                        $TraceKey1 = (Get-ItemProperty -Path "HKLM:\Software\Gladinet").TraceLevel
                        $TraceKey2 = (Get-ItemProperty -Path "HKLM:\Software\WOW6432Node\Gladinet").TraceLevel
                        If (($TraceKey1) -and ($TraceKey2)) {

                            Write-Output 'Detected enabled trace via registry. Continuing...'
                        }

                        Elseif (($TraceKey1) -and (-Not($TraceKey2))) {

                            Write-Warning -Message "Trace registry detected in HKLM:\Software\Gladinet, but not in HKLM:\Software\WOW6432Node\Gladinet"

                            $MainScreen.Hide()
                            $Shell = New-Object -ComObject "WScript.Shell"
                            $Button = $Shell.Popup("Please ensure the Trace key exist under HKLM:\Software\WOW6432Node\Gladinet, or enable from Diagnostics screen, then press Ok to continue ", 0, "Server Agent Debug Trace", 0)
                            $MainScreen.Show()
                        }

                        Elseif ((-Not(($TraceKey1)) -and $TraceKey2)) {

                            Write-Warning -Message "Trace registry detected in HKLM:\Software\WOW6432Node\Gladinet, but not in HKLM:\Software\Gladinet"
                            $MainScreen.Hide()
                            $Shell = New-Object -ComObject "WScript.Shell"
                            $Button = $Shell.Popup("Please ensure the Trace key exist under HKLM:\Software\Gladinet, or enable from Diagnostics screen, then press Ok to continue ", 0, "Server Agent Debug Trace", 0)
                            $MainScreen.Show()
                        }

                        Else {

                            $MainScreen.Hide()
                            $Shell = New-Object -ComObject "WScript.Shell"
                            $Button = $Shell.Popup("Enable trace from: Management console >> Diagnostics >> Enable Tracing.  Once enabled, click OK to continue", 0, "Server Agent Debug Trace", 0)
                            $MainScreen.Show()
                        }
                    }

                    Elseif ($Version.ProductName -eq 'WindowsClient') {

                        $TraceKey1 = (Get-ItemProperty -Path "HKLM:\Software\Gladinet").TraceLevel
                        $TraceKey2 = (Get-ItemProperty -Path "HKLM:\Software\WOW6432Node\Gladinet").TraceLevel
                        If (($TraceKey1) -and ($TraceKey2)) {

                            Write-Output 'Detected enabled trace via registry. Continuing..'
                        }

                        Elseif (($TraceKey1) -and (-Not($TraceKey2))) {

                            Write-Warning -Message "Trace registry detected in HKLM:\Software\Gladinet, but not in HKLM:\Software\WOW6432Node\Gladinet"
                            $Shell = New-Object -ComObject "WScript.Shell"
                            $Button = $Shell.Popup("Please ensure the Trace key exist under HKLM:\Software\WOW6432Node\Gladinet, or enable from Diagnostics screen, then press Ok to continue ", 0, "Server Agent Debug Trace", 0)
                        }

                        Elseif ((-Not(($TraceKey1)) -and $TraceKey2)) {

                            Write-Warning -Message "Trace registry detected in HKLM:\Software\WOW6432Node\Gladinet, but not in HKLM:\Software\Gladinet"
                            $Shell = New-Object -ComObject "WScript.Shell"
                            $Button = $Shell.Popup("Please ensure the Trace key exist under HKLM:\Software\Gladinet, or enable from Diagnostics screen, then press Ok to continue ", 0, "Server Agent Debug Trace", 0)
                        }

                        Else {

                            $Shell = New-Object -ComObject "WScript.Shell"
                            $MainScreen.Hide()
                            $Button = $Shell.Popup("Enable debug trace from the Windows client.  Once enabled, click OK to continue", 0, "Windows Client Debug Trace", 0)
                        }
                    }

                    Elseif ($Version.ProductName -eq 'CloudServer') {

                        Write-Output 'Enabling Server Trace from web.config file'
                        Set-CloudServerTrace -Enable True 
                    }

                    Set-DBGView -Version $Version.ProductName 

                    #Disabling steps recorder/traces
                    If ($StepsRecorder) {

                        Enable-StepsRecorder -Stop
                    }

                    If ($Version.ProductName -eq 'CloudServer') {

                        Write-Output 'Disabling Server Trace from web.config file'
                        Set-CloudServerTrace -Enable False 
                    }
                
                    If ($Version.ProductName -eq 'ServerAgent') {

                        $Shell = New-Object -ComObject "WScript.Shell"
                        $Button = $Shell.Popup("Disable trace", 0, "Server Agent Debug Trace", 0)
                    }

                    Elseif ($Version.ProductName -eq 'WindowsClient') {

                        $Shell = New-Object -ComObject "WScript.Shell"
                        $Button = $Shell.Popup("Disable debug trace from the Windows client.  Once disabled, click OK to continue", 0, "Windows Client Debug Trace", 0)
                    }
                }

                Elseif ($Pack) {
                
                    If ($FileSysDB) {

                        Export-ClientTrace -ProductName $Version.Productname -FileSysDB | Out-Null
                    }

                    Else {

                        Export-ClientTrace -ProductName $Version.Productname | Out-Null
                    }
                }

                Elseif ($WindbgInstall) {

                    Install-WinDBG -Product $Version.ProductName
                    #creates instructions in the Temp drive on steps to collect traces. 
                }

                Elseif ($WindbgUninstall) {

                    Uninstall-WinDBG -Product $Version.ProductName
                }

                elseif ($DownloadpdbFiles) {

                    $ExpandArchiveDestination = "$Env:USERPROFILE\Downloads"

                    If (-Not(Test-Path -Path "$Env:USERPROFILE\Downloads\Symbols")) {

                        Write-Output "Creating folder under $Env:USERPROFILE\Downloads\Symbols"
                        New-Item -Path "$ExpandArchiveDestination\Symbols" -ItemType Directory -Force
                    }

                    New-WinDdbgInstructions
                    #Downloads PDB Files for the Windows Client. 
                    If ($Version.Productname -eq 'WindowsClient' -or $Version.Productname -eq 'ServerAgent' ) {

                        Write-Output "Downloading pdb files for Client version $($Version.ProductVersion)"
                        Get-Winpdbfiles -WinVersion $Version.ProductVersion

                        #Add logic under this line to also check for server agent / CS server pdb files.
                        $GServiceMainServiceCheck = Get-Service -Name GserviceMain -ErrorAction SilentlyContinue

                        If (($Version.ProductName -eq 'WindowsClient') -or ($GServiceMainServiceCheck)) {

                            $ButtonType = [System.Windows.MessageBoxButton]::YesNo
                            $MessageIcon = [System.Windows.MessageBoxImage]::Warning   
                            $MessageBody = "Would you like to download the CloudServer Symbol files?"
                            $MessageTitle = "CloudServer Pdb file download"
                            $Result = [System.Windows.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon)

                            If ($Result -eq 'Yes') {

                                If ($Version.Productname -eq 'WindowsClient') { 

                                    $CSSymbolsVersion = ($Version).InstallationPath + '\' + 'ClientShell.exe'
                                    $CSVersion = ((Get-Item -Path $CSSymbolsVersion -ErrorAction SilentlyContinue -ErrorVariable MyErr).VersionInfo).ProductVersion
                                }

                                Else { 

                                    $CSVersion = (Get-Item -Path "$($Version.InstallationPath)\GladServerAgentService.exe").VersionInfo.FileVersion
                                }

                                If (-Not($CSVersion)) {

                                    Write-Error -Message "Script was unable to Download Server PDB Files."
                                    Write-Output $MyErr
                                }

                                Else { 

                                    Write-Output "Downloading CentreStrack version $CSVersion"
                                    Get-CSpdbfiles -CSversion $CSVersion
                                }
                            }
                        }
                    }

                    Elseif ($Version.Productname -eq 'CloudServer') {

                        Write-Output "Downloading pdb files for Cloud Server version $($Version.ProductVersion)"
                        Get-CSpdbfiles -CSVersion $Version.ProductVersion   
                    }
                }
            }

            Else {

                Write-Error -Exception 'Gladinet Solution not found' -Message 'Was not able to start trace due to missing solution. Please make sure the client is running.'
                $ProgressBox.AppendText( "No Gladinet solution found.`r`n" )
            }
        }

        End {

        }

    }
    #The Functions below are the helpter functions used by the GladTrace function.

    #Import-DBG downloads Debug View from https://docs.microsoft.com/en-us/sysinternals/downloads/debugview.
    Function Import-DBGView {
        [cmdletbinding()]
        Param (

            $DebugViewFolderPath = "$Env:USERPROFILE\Downloads",
            $DownloadLink = "https://download.sysinternals.com/files/DebugView.zip"
        )

        $ProgressBox.AppendText( "Downloading Debug View from $DownloadLink`r`n" )
        $Result = [PSCustomObject]@{

            Download = '';
        }

        Try {
        
            #By default powershell uses TLS 1.0 the sysinternal site security requires TLS 1.2
            [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
            Invoke-WebRequest -Uri $DownloadLink -OutFile "$DebugViewFolderPath\DBGView.zip" -ErrorAction Stop -UseBasicParsing
        }
        Catch [System.Net.WebException] {

            $ProgressBox.AppendText( "Could not download Debug View.  Check the $DownloadLink`r`n" )
            Write-Error -Message "Failed to validate the DBGViwer url from: https://docs.microsoft.com/en-us/sysinternals/downloads/debugview. 
                Please check internet connectivity or verify the provided URL: $DownloadLink" -Exception CouldNotConnect
        
            $Result.Download = 'Failed'
            Return
        }
        
        #Path for the unzipped DBGView folder
        $ExpandArchiveDestination = "$DebugViewFolderPath\DebugView" 

        #Path where the zip file got saved to.
        $DownloadPath = "$DebugViewFolderPath\DBGView.zip"

        #Unblocks the zip file, then proceeds with expanding the WinDBGViewer.zip
        Get-ChildItem -Path $DownloadPath | Unblock-File 

        Add-type -AssemblyName "System.IO.Compression.FileSystem" 
        [System.IO.Compression.ZipFile]::ExtractToDirectory($DownloadPath, $ExpandArchiveDestination)

        #Gets the folder named DBGView, if it finds it, then proceed with removing original dbg view zip file. 
        #This is done to maintain clean environment as script is executing. 
        $DebugViwerFolder = Get-Item -Path "$DebugViewFolderPath\DebugView" 

        If ($DebugViwerFolder) {

            $ProgressBox.AppendText( "Debug view extracted sucessfully.`r`n" )

            Try {

                #Remove DGG zip file from $DebugViewFolderPath folder.
                Remove-Item -Path "$DebugViewFolderPath\DBGView.zip" -Force -Recurse
            }

            Catch {
            
                Write-Output $_
            }

            $Result.Download = 'Success'
            Write-Output $Result
            Return
        }
        Else {
        
            Write-Output $_
            Return
        }
    } 
    #Set-DBGView configures Debug View based on the installed version.
    Function Set-DBGView {

        [Cmdletbinding()]
        Param (

            [String]$DebugExePath = "$Env:USERPROFILE\Downloads\DebugView\",

            [Parameter(Mandatory = 'true',
                ValueFromPipeline = 'true')]
            [String]$Version
        )

        Begin {

            $ProgressBox.AppendText( "Starting Debug View for $Version.`r`n" )

            If (-Not(Test-Path -Path "$Env:USERPROFILE\Downloads\DebugView")) {

                Import-DbgView
            }

            Else {

                $RunningDBGProcesses = Get-Process -Name 'DBGView' -ErrorAction SilentlyContinue

                If ($RunningDBGProcesses) {

                    Write-Verbose -Message 'Debug View Process found running. Terminating running Debug View Process.'
                    $RunningDBGProcesses | Stop-Process -Force
                    Write-Warning -Message 'Terminating existing running debug view Process.'
                }

                Else {
                    
                    Write-Output 'No Running Debug View processes found. Continuing..'
                }
            }

            Write-Verbose -Message 'Changing to Debug View directory'
            Push-location -Path $DebugExePath
        }

        Process {

            #####DBGViewer Parameters#####
            <#
            Parameters for DBGViewer 
            "/accepteula" = Silently accept end user license agreement
            "/t" = Run from Tray
            "/g" = Enable Capture Script Win32
            "/l" = The log filename
            "/k = Capture kernel output"
                #>
            ############################
            
            Write-Verbose -Message 'Getting Debug View file found.'
            $ElevatedSessionCheck = {

                Write-Verbose -Message 'Checking for elevated PowerShell session.'
                $ElevatedPrompt = [Security.Principal.WindowsIdentity]::GetCurrent()
                (New-Object Security.Principal.WindowsPrincipal $ElevatedPrompt).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) 
            }

            #Invokes $elevated session script block to verify current session is running as Administrator.
            $ElevatedPrompt = Invoke-Command $ElevatedSessionCheck

            $LogCount = (Get-ChildItem | Where-Object { $_.Name -match 'CS-DBGTraceCollect' }).count

            If ($Version -eq 'ServerAgent' -or $Version -eq 'WindowsClient') {
                
                Write-Verbose -Message "$($Version) detected.  Configuring Debug View accordingly.."

                $Arguements = @("/Accepteula", "/t", "/g", "/l", "CS-DBGTraceCollect$LogCount.txt")
                Write-Verbose -Message ':: Launching DBGView.exe'
            }

            Else {
        
                Write-Verbose -Message "Cloud Server server detected. Configuring Debug View accordingly.."
                $Arguements = @("/Accepteula", "/t", "/g", "/k", "/l", "CS-DBGTraceCollect$LogCount.txt")
            }

            If ($ElevatedPrompt) {

                $ProgressBox.AppendText( "Elevated Session detected.`r`n" )
                $MainScreen.Hide()
                Start-Process "$DebugExePath\Dbgview.exe" -ArgumentList $Arguements 
                $DebugViewProcess = Get-Process -Name DbgView
                #This is the OK Screen that operator selects OK once issue is done being reproduced.
                $Shell = New-Object -ComObject "WScript.Shell"
                $Button = $Shell.Popup("Click OK after issue has been reproduced", 0, "Gladinet trace collect", 0)
                $MainScreen.Show()

                $RunningDBGProcesses = Get-Process -Name 'DBGView' -ErrorAction SilentlyContinue
                If ($RunningDBGProcesses) {
        
                    #Values used for Write-Progress
                    Write-Verbose -Message 'Waiting for Debug View to terminate.'
                    $x = 0;
                    $Terminate_Count = 5 

                    $RunningDBGProcesses = Get-Process -Name 'DBGView' -ErrorAction SilentlyContinue

                    Write-Warning -Message 'Terminating Debug View Process.'
                    $Arguements = @('/q')
                    Start-Process "$DebugExePath\Dbgview.exe" -ArgumentList $Arguements
                    Start-Sleep -Seconds 10

                    $ProgressBox.AppendText( "Trying to terminate the Debug View Process.`r`n" )

                    While ($DebugViewProcess.HasExited -ne $true) {


                        Start-Process "$DebugExePath\Dbgview.exe" -ArgumentList $Arguements
                        $x++
                        Write-Progress -Activity "$x of $Terminate_Count tries before continuing" -Status  'Closing Debug View' -PercentComplete (($x / $Terminate_Count) * 100)

                        If ($x -gt $Terminate_Count) {

                            $ProgressBox.AppendText( "Took too long to terminate the Debug View Process...Continuing... .`r`n" )
                            $ProgressBox.AppendText( "If Capturing again, ensure that the Debug View Process is not running.`r`n" )
                            break
                        }

                        Start-Sleep -Seconds 1
                    }
                }

                Else {
                }
            }

            Else {

                $ProgressBox.AppendText( "Non-Elevated PowerShell Session detected.`r`n" )
                Write-Output "Once the issue has been reproduced, launch DebugView from the System tray and close out the process."    
                $adminProcessHandle = Start-Process "$DebugExePath\Dbgview.exe" -ArgumentList $Arguements -Verb RunAs -PassThru -WindowStyle Minimized 

                $MainScreen.Hide()
                $Shell = New-Object -ComObject "WScript.Shell"
                $Button = $Shell.Popup("Double click Debug View from the system tray and close out of it to continue.", 0, "Gladinet trace collect", 0)

                While ($adminProcessHandle.HasExited -ne $True) {

                    Write-Output 'Waiting for Debug View Process termination to proceed.'
                    Start-Sleep -Milliseconds 2000
                }

                $MainScreen.Show()
            }
        }

        End {

            $TraceVerification = get-content "$DebugExePath\CS-DBGTraceCollect$LogCount.txt" 
            $WowSettingDBVer = $TraceVerification |  Select-String -Pattern 'WOSSettingsDB'
            $FileSysSDKCheck = $TraceVerification |  Select-String -Pattern 'FilsSysSDK'

            If (($Version -eq 'ServerAgent' -or $Version -eq 'WindowsClient') -and (-Not($WowSettingDBVer) -and (-Not($FileSysSDKCheck)))) {

                $ProgressBox.AppendText( "DebugView Trace Acceptance Test: Fail`r`n") 
                $ProgressBox.AppendText( "Please ensure that trace has been enabled`r`n")
            }

            Else {

                $ProgressBox.AppendText("DebugView Trace Acceptance Test: Pass`r`n")
            }

            Pop-Location        
        }
    }
    #Sets web.config CanTrace and creates web.config backup before modifying. Recycles namespace application pool.
    Function Set-CloudServerTrace {

        [cmdletbinding()]
        Param(

            [Parameter(Mandatory = $True)]
            [ValidateSet('True', 'False')]
            [String]$Enable
        )

        Begin {

            $ProgressBox.AppendText("Setting Cloud Server trace")
            Write-Verbose -Message "Checking Cloud Server server installation path."

            $InstallDir = (Get-ItemProperty "HKLM:\Software\Gladinet\Enterprise" -ErrorAction SilentlyContinue).installdir

            If (-Not($InstallDir)) {
                
                $InstallDir = (Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Gladinet\Enterprise').installdir

                If (-Not($InstallDir)) {

                    Throw 'Could not locate cloud server installation path. Please perform Process manually.'
                    Start-Sleep -Seconds 
                    Exit
                }
            }

            $webConfigPath = "$InstallDir\root\web.config"
        }

        Process {

            #If an installation directory is found, proceed with evaluating -Enable value. 
            If (Test-Path -Path $webConfigPath) {

                $ProgressBox.AppendText("Web.Config file found.`r`n")
                # month_day_year - hours_mins_seconds used to append to the end of the web.config file copy under the signed in user's Download's folder.
                $currentDate = (get-date).tostring("MM_dd_yyyy-hh_mm_s") 
                
                $BackupPath = "$Env:USERPROFILE\Downloads\WebConfigBackups"
                If (-Not(Test-Path -Path $BackupPath)) {

                    New-Item -Path $BackupPath -ItemType Directory
                }

                $backup = "$BackupPath\Web.config" + "_$currentDate"  
                #Reads the web.config file
                $xml = [xml](get-content $webConfigPath)
                $root = $xml.get_DocumentElement();
                $Key = 'CanTrace'

                #Checks the AppSetting key entries, if the Can Trace entry is found, proceed with evaluating -Enable value. 
                If (($root.appSettings.add | Where-Object { $_.Key -eq $Key })) {

                    Write-Verbose 'Trace entry found in config file'
                    $ProgressBox.AppendText("Trace entry found in web.config file, setting it to true.`r`n")
                    #If Enable switch is off, set CanTrace value to off. 
                    If ($Enable -eq 'False') {

                        $ProgressBox.AppendText("Setting CanTrace value to false.`r`n")
                        ($root.appSettings.add | Where-Object { $_.Key -eq $Key }).value = 'false'
                        $xml.Save($webConfigPath)
                        Return
                    }

                    #IF its anything Else set CanTrace value to true.
                    Else {

                        $xml.Save($backup)
                        $ProgressBox.AppendText("Setting CanTrace value to true.`r`n")
                        Write-Verbose 'Setting web.config trace value to true.'
                        ($root.appSettings.add | Where-Object { $_.Key -eq $Key }).value = 'true'
                    }
                }

                #If the CanTrace Setting is not found under the AppSettings from the web.config file, proceed with creating the entry.
                Else {

                    #Creates the web.config copy
                    Write-Verbose -Message "Creating backup for the web.config file"
                    $xml.Save($backup)
        
                    If (Test-Path -Path $backup) {

                        $ProgressBox.AppendText("Web.config backup file created.`r`n")
                    }

                    Else {

                        $ProgressBox.AppendText("Failed to create backup of config file. Terminating script.")
                        Exit
                    }

                    Write-Warning 'CanTrace value not found under web.config.  Creating a new entry and setting its value to true.'
                    'No trace entry found under the web.config file. Creating a new entry.' >> $LogFile
                    Write-Verbose -Message "CanTrace web.config file not found"

                    $newElement = $xml.CreateElement("add");
                    $nameAtt1 = $xml.CreateAttribute("key")
                    $nameAtt1.psbase.value = $Key;
                    $newElement.SetAttributeNode($nameAtt1);

                    $nameAtt2 = $xml.CreateAttribute("value");
                    $nameAtt2.psbase.value = 'true';
                    $newElement.SetAttributeNode($nameAtt2);

                    $xml.configuration["appSettings"].AppendChild($newElement);

                    'Restarting namespace application pool after creating new CanTrace value and setting it to true. ' >> $LogFile
                }
        
                $xml.Save($webConfigPath)
                Restart-WebAppPool "Namespace"
            }

            Else {

                #If installation path is not found, return installation path not found.
                'Could not find installation path.' >> $LogFile
                Write-Error -Message "$webConfigPath not found"   
                Exit
            }
        }

        End {
        }
    }
    #Enables Windows Steps Recorder. 
    Function Enable-StepsRecorder {

        [CmdletBinding()]
        param (

            [Switch]$Start,
            [Switch]$Stop,
            [String]$OutPath
        )

        Begin {   
        }

        Process {

            If ($Start) {

                If (Test-Path -path "$env:systemdrive\Windows\System32\psr.exe") {
                
                    $MainScreen.Hide()
                    $ButtonType = [System.Windows.MessageBoxButton]::YesNo
                    $MessageIcon = [System.Windows.MessageBoxImage]::Warning   
                    $MessageBody = "Windows Steps Recorder has been enabled. Please close down any sensitive content, as screenshots of the screeen will be taken. Would you like to continue?"
                    $MessageTitle = "Screenshot capture disclosure"
                    $Approval = [System.Windows.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon)

                    If ($Approval -eq 'Yes') {

                        psr.exe /start /gui 0 /output $Outpath
                        Write-Output   'Windows Step Recorder enabled.'
                    }

                    Else {

                        Write-Output 'Screenshot capture aborted.'
                    }
                }

                Else {
                
                    Write-Error -Exception 'PSR.EXE not found under the SystemDrive folder' -Message "The Problem steps recorder was not found
                    under the $env:systemdrive\Windows\System32. Please try launching it manually"
                    Continue
                }
            }

            Elseif ($Stop) {

                Write-Output 'Closing down Windows Steps Recorder.'
                Write-Verbose -Message 'Disabling Windows Step Recorder'
                
                #$PsrProcess = Get-Process -Name Psr -ErrorAction SilentlyContinue (delete line if not needed)
                psr.exe /stop 

                Write-Verbose -Message 'Waiting for Step Recorder to finish saving'
            }
        }

        End {
        }
    }
    #Copies FileSysDB, Logs, Debug View trace, and zips.
    Function Export-ClientTrace {
        [cmdletbinding()]
        Param (

            [String]$ProductName, 
            [Switch]$FileSysDB
        )

        Begin {

            [Int32]$LogCount = 5
            $OutPath = "$Env:USERPROFILE\Downloads"
            $ZipOutpath = $OutPath
        }

        Process {

            $gteamclientPath = $Version.gteamclientpath

            Start-SystemAnalysis -Product $ProductName -Outpath "$OutPath\GladinetTraceCollect"
            If ($Version.Productname -eq 'ServerAgent' -or $Version.Productname -eq 'WindowsClient') {

                If (-Not(Test-Path "$OutPath\GladinetTraceCollect\logging")) {

                    Write-Output 'Creating folder in the GladinetTraceCollect folder'
                    New-Item -Path "$OutPath\GladinetTraceCollect" -Name logging -ItemType Directory -Force
                }

                #Copies gsettings file. 
                Copy-Item -Path "$($Version.gteamclientpath)\gsettings.db" -Destination "$OutPath\GladinetTraceCollect\gsettings.db" -Force

                If ($Version.FileSysDBPath) {

                    Write-Output 'Copying over the FileSysDB folder'
                    $ProgressBox.AppendText( "FileSysDB Folder found. Copying...`r`n" )
                    $FileSysDBpath = $version.FileSysDBPath
                    If (Test-Path $FileSysDBpath -ErrorAction SilentlyContinue) {
                        
                        $FileSysSize = Get-ChildItem -Path $FileSysDBpath -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable MyErr | 
                        Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue
                    
                        If (($FileSysSize.Sum / 1GB) -gt 5) {

                            Write-Output "FilesysDB folder size $($FileSysSize.Sum/1MB) MB"
                            $FileSysDbCopyBtn = [System.Windows.MessageBoxButton]::YesNo
                            $MessageIcon = [System.Windows.MessageBoxImage]::Warning   
                            $MessageBody = "The FileSysDB folder is larger than the warning threshold of 5 GB.  Would you still like to continue?"
                            $MessageTitle = "FileSysDB Size Notice"

                            $FileSysDbCopyApproval = [System.Windows.MessageBox]::Show($MessageBody, $MessageTitle, $FileSysDbCopyBtn, $MessageIcon)

                            If ($FileSysDbCopyApproval -eq 'Yes') {

                                $ProgressBox.AppendText( "Copying FileSysDB`r`n" )
                                Copy-Item -Path $FileSysDBpath -Destination "$OutPath\GladinetTraceCollect\" -Recurse -Force
                            }
                            
                            Else {

                                $ProgressBox.AppendText( "Skipping copying FileSysDb.`r`n" )
                            }
                        }

                        Else {

                            Copy-Item -Path $FileSysDBpath -Destination "$OutPath\GladinetTraceCollect\" -Recurse -Force
                        }
                    }
                }

                Else {

                    $ProgressBox.AppendText( "No FileSysDB directory found under gteamclient`r`n" )
                }
            }

            Elseif ($ProductName -eq 'CloudServer') {
        
                Write-Output 'Cloud Server Detected, Continuing'
                Return
            }
        }

        End {


            If (Test-Path -Path "$OutPath\DebugView\CS-DBGTraceCollect*") {

                Copy-Item -Path "$OutPath\DebugView\*" -Filter "CS-DBGTraceCollect*" -Destination "$OutPath\GladinetTraceCollect\"
                Remove-Item -Path "$OutPath\DebugView\*" -Filter "CS-DBGTraceCollect*"
            }

            Else {
                
                Write-Output 'No Debug traces found in the DebugView folder.'
            }

            $Content = (Get-Item -Path $OutPath\GladinetTraceCollect).FullName

            [Reflection.Assembly]::LoadWithPartialName( "System.IO.Compression.FileSystem" ) | Out-Null
            [System.AppDomain]::CurrentDomain.GetAssemblies() | Out-Null

            $src_folder = "$Content"
            $destfile = "$OutPath\GladinetTraceCollect-$($Version.ProductName)-$currentDate.Zip"
            $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
            $includebasedir = $false

            If ($ProductName -eq 'WindowsClient' -or $ProductName -eq 'ServerAgent') {

                
                Get-Item -Path "$($Version.gteamclientpath)\logging\*" | Sort-Object -Property LastWriteTime -Descending | 
                Select-Object -First $LogCount | Copy-Item -Destination "$OutPath\GladinetTraceCollect\logging" -Force

                [System.IO.Compression.ZipFile]::CreateFromDirectory("$ZipOutpath\GladinetTraceCollect\logging", "$OutPath\GladinetTraceCollect\logging.zip", 
                    $compressionLevel, $includebasedir)

                If (Test-Path -Path "$OutPath\GladinetTraceCollect\logging.zip") {

                    Write-Output 'Logging folder compressed.'
                    Write-Verbose 'Compresses loggings folder'
                    Remove-Item -Path "$OutPath\GladinetTraceCollect\logging" -Force -Recurse
                }
            
                If ((Test-Path -path "$OutPath\GladinetTraceCollect\FileSysDB") -and ($FileSysDB)) {

                    [System.IO.Compression.ZipFile]::CreateFromDirectory( "$ZipOutpath\GladinetTraceCollect\FileSysDB", 
                        "$ZipOutpath\GladinetTraceCollect\FileSysDB.zip", $compressionLevel, $includebasedir)
                    Remove-Item -Path "$OutPath\GladinetTraceCollect\FileSysDB" -Recurse -Force
                }
            }

            [System.IO.Compression.ZipFile]::CreateFromDirectory($src_folder, $destfile, $compressionLevel, $includebasedir)

            $ProgressBox.text = Write-Output "Content has been zipped to $OutPath\GladinetTraceCollect-$($Version.ProductName)-$currentDate.Zip`r`n"
            Remove-Item -Path "$OutPath\GladinetTraceCollect" -Force -Recurse -Confirm:$false
        }
    }
    #Downloads WinDBg to the Downloads folder. 
    Function Install-WinDBG {

        [CmdletBinding()]
        param (

            [string]$Downloadlink = 'https://go.microsoft.com/fwlink/p/?linkid=2120843',
            [String]$OutPath = "$Env:USERPROFILE\Downloads\WinDBG.exe",
            [string]$Product
        )

        Begin {
        }

        Process {

            Invoke-WebRequest -Uri $Downloadlink -OutFile $OutPath -UseBasicParsing -ErrorAction SilentlyContinue

            If (Test-Path -Path $OutPath) {

                $Arguements = @("/features OptionID.WindowsDesktopDebuggers /quiet")
                Start-Process $OutPath -ArgumentList $Arguements 

                $StatusResult = [PSCustomobject] @{
                
                    'Installation' = ''
                }

                $errCount = 0
                $Installed = 'false'
                while ( $Installed -ne 'true') {
                
                    $debuggerDir = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers" -ErrorAction SilentlyContinue

                    $WinDbgProgressBox.text = "Installing...`r`n"
                    $errCount++
                
                    If ($debuggerDir) {
                    
                        Write-Output 'WinDBG Installation found'
                        $Installed = 'true'
                        $StatusResult = [PSCustomobject] @{
                
                            'Installation' = 'Success'
                        }

                        If ($Product -eq 'WindowsClient' -or $Product -eq 'ServerAgent') {

                            $SOSdllFile = Get-Item "$Env:SystemDrive\Windows\Microsoft.NET\Framework\v4.0.30319\SOS.dll"
                            $WindbgPath = "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x86"
                        }

                        Elseif ($Product -eq 'CloudServer') {

                            $SOSdllFile = Get-Item "$Env:SystemDrive\Windows\Microsoft.NET\Framework64\v4.0.30319\SOS.dll"
                            $WindbgPath = "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64"
                        }

                        Write-Output "Wrapping things up with WinDBG installation."
                        Start-Sleep -Seconds 10
                        
                        $ElevatedSessionCheck = {

                            Write-Verbose -Message 'Checking for elevated PowerShell session.'
                            $ElevatedPrompt = [Security.Principal.WindowsIdentity]::GetCurrent()
                            (New-Object Security.Principal.WindowsPrincipal $ElevatedPrompt).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) 
                        }

                        #Invokes $elevated session script block to verify current session is running as Administrator.
                        $ElevatedPrompt = Invoke-Command $ElevatedSessionCheck

                        If ($ElevatedPrompt) {

                            Copy-Item -Path $SOSdllFile -Destination "$WindbgPath\SOS.dll" -Force
                        }

                        Else {

                            Write-Output 'Non-Elevated Session detected. Administrator rights are needed to copy system SOS.dll file to
                                the WinDbg/debugger directory'

                            Start-Process PowerShell.exe -ArgumentList "Copy-Item -Source $SOSdllFile -Destination $WindbgPath\SOS.dll" -Wait -Verb RunAs
                            #Copy-Item -Path $SOSdllFile -Destination "$WindbgPath\SOS.dll" -Force
                        }

                        Write-Output $StatusResult
                    }

                    Elseif ($errCount -eq 30) {                       
                        
                        Write-Error 'Installation check timed out. Script was unable to find \Program Files (x86)\Windows Kits\10\Debuggers'
                        $StatusResult = [PSCustomobject] @{
                
                            'Installation' = 'failed'
                        }
                        Write-Output $StatusResult
                    }

                    Else {

                        Write-Warning 'Waiting for WinDBG installation'
                        Start-Sleep -Seconds 5
                    }
                }
            }
        }

        End {

        }
    }
    #Uses downloaded installer from Install-WinDBG function to call the WinDBG uninstallation prompt. 
    Function Uninstall-WinDBG {

        [cmdletbinding()]
        Param (

            [string]$WinDBGexePath = "$Env:USERPROFILE\Downloads\Windbg.exe",
            [string]$Product 
        )

        If ($Product -eq 'WindowsClient' -or $Product -eq 'ServerAgent') {

            $WindbgPath = "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x86"
        }

        Elseif ($Product -eq 'CloudServer') {

            $WindbgPath = "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64"
        }

        $SOSdllPath = "$WindbgPath\SOS.dll"

        If (Test-Path -Path "$WindbgPath\SOS.dll" ) {

            Remove-Item -Path $SOSdllPath
        }

        $Arguements = @("/uninstall")
        Start-Process $WinDBGexePath -ArgumentList $Arguements 
    }
    #Downloads Windows/Server Agent pdb files based on istalled version.
    Function Get-Winpdbfiles {
        [CmdletBinding()]
        param (
            [string]$WinVersion,
            [switch]$Download,
            [string]$Outfile = "$Env:USERPROFILE\Downloads"
        )

        begin {

            $SymbolLinks = ( 
                'http://wcbuildm.gladinet.com/builds/pdbs/',
                'http://wcbuild.gladinet.com/builds/pdbs/',
                'http://wcbuild.gladinet.com/releases/pdbs/'
            )
        }

        process {

            Foreach ($Link in $SymbolLinks) { 
                
                $Result = Invoke-WebRequest -Uri $Link -UseBasicParsing

                $WinVer = $Result.Links.href | Where-Object { $PSItem -match $version.ProductVersion }
                If ($WinVer) { 
                    
                    Write-Output "Matching symbol link found"
                    break
                }
                Else { 
                    
                    Continue
                }
            }

            $pdbZipFilename = $WinVer
            $buildNum = $WinVersion.Split('.')[2]
            Write-Output $pdbZipFilename
            $zipDownloadLink = 'http://' + $Link.Split('/')[2] + "$pdbZipFilename" + 'pdb' + "$buildNum.zip"


            Invoke-WebRequest -Uri $zipDownloadLink -OutFile "$Env:Userprofile\Downloads\Symbols\$buildNum.zip" -UseBasicParsing
        }
        end {

             #extract the downloaded zip file to the downloads folder
             Add-type -AssemblyName "System.IO.Compression.FileSystem" 
                [System.IO.Compression.ZipFile]::ExtractToDirectory("$Env:Userprofile\Downloads\Symbols\$buildNum.zip", "$Env:Userprofile\Downloads\Symbols\$buildNum")
                
                #If symbols zip file extracts, delete it afterwards. 
                If ("$Env:Userprofile\Downloads\Symbols\$buildNum") { 
                    
                    Remove-Item -Path "$Env:Userprofile\Downloads\Symbols\$buildNum.zip" -Force
                }
        }
    }
    #Downloads Cloud Server pdb files.
    Function Get-CSpdbfiles {
        [CmdletBinding()]
        Param (

            [string]$CSVersion
            #delete unused parameter
            #[switch]$Download
        )

        Begin {

            If (Test-Path -Path "$($Version.InstallationPath)\Namespace\bin\Userlib.dll") {

                $Namespace_Userlib_Version = Get-Item -Path "$($Version.InstallationPath)\Namespace\bin\Userlib.dll" -ErrorAction SilentlyContinue
                If ($Namespace_Userlib_Version.VersionInfo.ProductVersion -gt $CSVersion) {

                    $WinDbgProgressBox.Text = "\Namespace\Userlib.dll has a greater version than the Cloud Server version dected from the registry`r`n'"
                    $ButtonType = [System.Windows.MessageBoxButton]::YesNo
                    $MessageIcon = [System.Windows.MessageBoxImage]::Warning   
                    $MessageBody = "The Userlib.dll File version on this system is greater than the Cloud Server's version found in the System Registry. Would you like to download the symbol files for this version? (v$($Namespace_Userlib_Version.VersionInfo.ProductVersion))"
                    $MessageTitle = "Version mismatch detected."
                
                    $SymbolsApproval = [System.Windows.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon)
                    If ($SymbolsApproval -eq 'Yes') {

                        $CSVersion = $Namespace_Userlib_Version.VersionInfo.ProductVersion
                    }
                }
            }

            $TargetPdbVers = $CSVersion.Split('.')[2] + '.' + $CSVersion.Split('.')[3]

            $SymbolLinks = (
                "http://gcbuildr3.gladinet.com/builds/pdbs/",
                "http://gcbuild.gladinet.com/builds/pdbs/"
            )
        }

        process {

            Foreach ($Link in $SymbolLinks) { 

                $Moddedverse = $TargetPdbVers.Split('.')[-1]
                $CSpdbWebRequest = Invoke-WebRequest -Uri $Link -ErrorAction SilentlyContinue -UseBasicParsing
                $ziplink = $CSpdbWebRequest.links.href | Where-Object { $PSItem -like "*$Moddedverse*" }

                If ($ziplink) { 

                    Write-Output "Symbol link found."
                    Break
                }
                Else { 

                    Continue
                }
            }

            Write-Output $ziplink 
            $FileName = $ziplink.Split('.')[-2] + '.zip'
            $Link
            $URL = $Link.split('/')[0] +'//' + $Link.split('/')[2]
            Invoke-WebRequest -Uri ($URL + $ziplink)  -OutFile "$Env:USERPROFILE\Downloads\Symbols\CloudServer-$FileName" -UseBasicParsing
        }

        end {

            #extract the downloaded zip file to the downloads folder
             Add-type -AssemblyName "System.IO.Compression.FileSystem" 
                [System.IO.Compression.ZipFile]::ExtractToDirectory("$Env:USERPROFILE\Downloads\Symbols\CloudServer-$FileName", "$Env:USERPROFILE\Downloads\Symbols\CloudServer-$(($FileName.split('.')[0]))")
                
                #If symbols zip file extracts, delete it afterwards. 
                If ("$Env:USERPROFILE\Downloads\Symbols\CloudServer-$(($FileName.split('.')[0]))") { 
                    
                    Remove-Item -Path "$Env:USERPROFILE\Downloads\Symbols\CloudServer-$FileName" -Force
                }
        }
    }
    #Gets product information such as version and installation/gteamclient folder path. 
    Function Get-GladVersion {

        [Cmdletbinding()]
        param(

            [String]$WindowsClientGteamDir = "$Env:LOCALAPPDATA\gteamclient",
            [String]$ServerAgentGteamClientDir = "$Env:ProgramData\gteamclient",
            [String]$LogFile = "$Env:USERPROFILE\Downloads\GladTraceCollect_Log.txt",
            [Switch]$FileSysDB 
        )

        Begin {
        
            #If this key exist, the solution is ServerSolution
            $SignedInUser = (WhoAmI).Split('\')[1]

            $CloudServerKeyPath = "HKLM:\SOFTWARE\Gladinet\Enterprise"
            $CloudServerKeyPath2 = 'HKLM:\SOFTWARE\WOW6432Node\Gladinet\Enterprise'

            $InstallationObject = [PSCustomObject] @{
                HostName         = '';
                Productname      = '';
                ProductVersion   = '';
                InstallationPath = '';
                UpdateHost       = '';
                gteamclientpath  = '';
                FileSysDBPath    = '';
            }
        }

        Process {

            If (Test-Path -Path $CloudServerKeyPath -ErrorAction SilentlyContinue) {

                $InstallationObject.HostName = $Env:COMPUTERNAME
                $InstallationObject.Productname = 'CloudServer'
                $InstallationObject.ProductVersion = (Get-Process GladinetCloudMonitor -ErrorAction SilentlyContinue).ProductVersion
                $InstallationObject.InstallationPath = (Get-ItemProperty -Path $CloudServerKeyPath2).InstallDir;
                $InstallationObject.UpdateHost = 'N/A'
                $InstallationObject.gteamclientpath = 'N/A'
                $InstallationObject.FileSysDBPath = 'N/A'

                If ($InstallationObject.ProductVersion -eq '1.0.0.0' ) {

                    $InstallationObject.ProductVersion = (Get-ItemProperty -Path "$($InstallationObject.InstallationPath)\namespace\bin\userlib.dll").VersionInfo.ProductVersion 
                }

                Write-Output $InstallationObject 
                Return
            }

            Elseif ((-not(Test-Path -Path $CloudServerKeyPath -ErrorAction SilentlyContinue)) -and (Test-Path -Path $CloudServerKeyPath2 -ErrorAction SilentlyContinue)) { 
                        
                Write-Output 'Legacy CentreStack Server installation detected.'
                $InstallationObject.HostName = $Env:COMPUTERNAME
                $InstallationObject.Productname = 'CloudServer'
                $InstallationObject.ProductVersion = (Get-ItemProperty -Path $CloudServerKeyPath\namespace\bin\userlib.dll -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
                $InstallationObject.InstallationPath = (Get-ItemProperty -Path $CloudServerKeyPath).InstallDir
                $InstallationObject.UpdateHost = 'N/A'
                $InstallationObject.gteamclientpath = 'N/A'
                $InstallationObject.FileSysDBPath = 'N/A'

                Write-Output $InstallationObject
                Return
            }

            $WinClientProductRegKey = (Get-ItemProperty 'HKLM:\SOFTWARE\Gladinet' -ErrorAction SilentlyContinue).Product
            $GladServices = Get-Service -Name GladGroupSVC, Gladrmountsvc, GladFileMonSvc -ErrorAction SilentlyContinue

            If (($WinClientProductRegKey -eq 'Cloud Windows Client') -or (Get-Process -Name 'CoDesktopClient' -ErrorAction SilentlyContinue) -or ($WinClientProductRegKey -eq 'Triofox Windows Client') `
                    -or ($WinClientProductRegKey -eq 'Gladinet Cloud Desktop' -and (Test-Path $Env:Userprofile\gteamclient -ErrorAction SilentlyContinue))) {

                $RegistryProps = Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Gladinet\AutoUpdate" -ErrorAction SilentlyContinue
                $SignedInUser = (WhoAmI).Split('\')[1]

                $InstallationObject.HostName = $Env:COMPUTERNAME
                $InstallationObject.Productname = 'WindowsClient'
                $InstallationObject.ProductVersion = $RegistryProps.CurrentVersion
                $InstallationObject.InstallationPath = $RegistryProps.InstallPath
                $InstallationObject.UpdateHost = $RegistryProps.UpdateHost
                $InstallationObject.gteamclientpath = "$Env:SystemDrive\Users\$signedInUser\AppData\Local\gteamclient"
                $InstallationObject.FileSysDBPath = 'N/A'

                If ($FileSysDB) {

                    $ExistingEmails = Get-childitem -path $InstallationObject.gteamclientpath  | Where-Object { $PSItem.Name -match '@' }
                    If ($ExistingEmails.count -gt 1) {

                        $MainScreen.hide()
                        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
                        $EmailAccount = [Microsoft.VisualBasic.Interaction]::InputBox('Multiple accounts found under the gteamclient folder. Please enter the email of the signed in account.', 
                            'Multiple Accounts Detected')
                        While ($EmailAccount -notin $ExistingEmails.Name ) {

                            Write-Output 'The email entered is not an email previously signed in.  Please try again'
                            $EmailAccount = [Microsoft.VisualBasic.Interaction]::InputBox('Multiple accounts found under the gteamclient folder. Please enter the email of the signed in account.', 
                                'Multiple Accounts Detected')
                        }

                        $InstallationObject.FileSysDBPath = "$Env:SystemDrive\Users\$signedInUser\AppData\Local\gteamclient\$EmailAccount\FileSysDB"
                        $MainScreen.show()
                    }

                    Else {
                
                        $InstallationObject.FileSysDBPath = "$($InstallationObject.gteamclientpath)\$($ExistingEmails.Name)\$EmailAccount\FileSysDB"
                    }
                }

                Write-Output $InstallationObject
                Return
            }

            Elseif (($WinClientProductRegKey -eq 'Cloud Server Agent') -or (Get-Service -Name 'GladGroupSvc' -ErrorAction SilentlyContinue) `
                    -or (Get-Service -Name 'GCServiceMain' -ErrorAction SilentlyContinue) -and (Test-Path -Path "$Env:ProgramData\gteamclient")) {

                $RegistryProps = Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Gladinet\AutoUpdate"
                $SignedInUser = (WhoAmI).Split('\')[1]

                $InstallationObject.HostName = $Env:COMPUTERNAME
                $InstallationObject.Productname = 'ServerAgent'
                $InstallationObject.ProductVersion = $RegistryProps.CurrentVersion
                
                #If Product version is empty, search for teh WOsDeviceFileSys file version
                If (-Not($RegistryProps.ProductVersion) -and (Test-Path -Path "$Env:ProgramFiles\Gladinet\Cloud Server Agent\WOSDeviceFileSys.dll")) { 

                    $InstallationObject.ProductVersion = (Get-ItemProperty -path "$Env:ProgramFiles\Gladinet\Cloud Server Agent\WOSDeviceFileSys.dll" -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
                }

                $InstallationObject.InstallationPath = $RegistryProps.InstallPath

                If (-Not($InstallationObject.InstallationPath) -and (Test-Path -Path "$Env:ProgramFiles\Gladinet\Cloud Server Agent")) { 

                    $InstallationObject.InstallationPath = "$Env:ProgramFiles\Gladinet\Cloud Server Agent"
                }
                $InstallationObject.UpdateHost = $RegistryProps.UpdateHost
                $InstallationObject.gteamclientpath = "$Env:ProgramData\gteamclient"

                $ExistingEmails = Get-childitem -path $InstallationObject.gteamclientpath  | Where-Object { $PSItem.Name -match '@' }

                If ($FileSysDB) {

                    $ExistingEmails = Get-childitem -path $InstallationObject.gteamclientpath  | Where-Object { $PSItem.Name -match '@' }
                    If ($ExistingEmails.count -gt 1) {

                        $MainScreen.hide()

                        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
                        $EmailAccount = [Microsoft.VisualBasic.Interaction]::InputBox('Multiple accounts found under the gteamclient folder. Please enter the email of the signed in account.', 
                            'Multiple Accounts Detected')
                        While ($EmailAccount -notin $ExistingEmails.Name ) {

                            Write-Output 'The email entered is not an email previously signed in.  Please try again'
                            $EmailAccount = [Microsoft.VisualBasic.Interaction]::InputBox('Multiple accounts found under the gteamclient folder. Please enter the email of the signed in account.', 
                                'Multiple Accounts Detected')
                                
                        }
                        $MainScreen.show()

                        $InstallationObject.FileSysDBPath = "$($InstallationObject.gteamclientpath)\$EmailAccount\FileSysDB"
                    }

                    Else {
                
                        $InstallationObject.FileSysDBPath = "$($InstallationObject.gteamclientpath)\$($ExistingEmails.Name)\FileSysDB"
                    }
                }

                Else {
                
                    $InstallationObject.FileSysDBPath = "$($InstallationObject.gteamclientpath)\$($ExistingEmails.Name)\FileSysDB"
                }

                Write-Output $InstallationObject
                Return
            }

            Else {

                Write-Output 'No Solution found'
                Write-Output $InstallationObject
            }
        }

        End {
        }
    }
    #Clears all Debug View traces under Downloads\debugview folder. 
    Function Clear-GladTraceLogs {
        [Cmdletbinding()]
        Param (

            $DbgTracesPath = "$Env:USERPROFILE\Downloads\DebuGView"
        )
        [System.Reflection.Assembly]::LoadWithPartialName("Windows.System.Form")
        If (Test-Path -Path "$DbgTracesPath\CS-DBGTraceCollect*") {

            Remove-Item -Path "$DbgTracesPath\CS-DBGTraceCollect*" -Force -Recurse
            $ProgressBox.Text = "Traces cleared."
        }

        else {

            $ProgressBox.Text = "No traces found.`r`n"
        }
    }
    Function New-WinDdbgInstructions { 

        $WinDbgProgressBox.Text = $null
        $WinDbgProgressBox.text += "---------WinDBG Notes---------`r`n"
        $WinDbgProgressBox.text += "1. MS Symbols: srv*C:\symbols*https://msdl.microsoft.com/download/symbols`r`n"
        $WinDbgProgressBox.text += "2. x kernel32!TerminateP*`r`n"
        $WinDbgProgressBox.text += "3. bp kernel32!TerminateProcessStub OR bp KERNEL32!TerminateProcess`r`n"
        $WinDbgProgressBox.text += "4. Type g to continue.`r`n"
        $WinDbgProgressBox.text += "5. If 64-bit Windbg: run !wow64exts.sw first`r`n"
        $WinDbgProgressBox.text += "6. kb`r`n"
        $WinDbgProgressBox.text += "7. ~*kb`r`n"
        $WinDbgProgressBox.text += "8. .load SOS.dll`r`n"
        $WinDbgProgressBox.text += "9. ~*e!ClrStack`r`n"
        $WinDbgProgressBox.text += "10. !analyze -v`r`n"
        $WinDbgProgressBox.text += "11. .dump /ma c:\temp\crash.dmp <Change file path>`r`n"
        $WinDbgProgressBox.text += "12. If Catching server thread: Only run .load SOS.dll and ~*e!ClrStack`r`n"
    }
    #Gathers system information such as Product information and basic hardware information, such as Memory and CPU in.
    Function Start-SystemAnalysis {

        [CmdletBinding()]
        Param (

            [String]$Outpath, 
            [String]$Product,
            [Switch]$IntervalProc
        )

        Begin {
        
            #CSS codes
            If (Test-Path -Path $Env:USERPROFILE\Downloads\GladinetTraceCollect\GladinetSystemAnalysis.html) {

                $ProgressBox.AppendText( "System Analysis already exist. Skipping...`r`n" )
                Return
            }

            $ProgressBox.AppendText( "GeneratingSystem Analysis Report...`r`n" )

            $header = @"
<style>

    h1 {

        font-family: Arial, Helvetica, sans-serif;
        color: #2596be;
        font-size: 28px;

    }
    
    h2 {

        font-family: Arial, Helvetica, sans-serif;
        color: #000099;
        font-size: 16px;

    }
    
table {

        font-size: 12px;
        border: 0px; 
        font-family: Arial, Helvetica, sans-serif;
    } 
    
    td {

        padding: 4px;
        margin: 0px;
        border: 0;
    }
    
    th {

        background: #395870;
        background: linear-gradient(#49708f, #293f50);
        color: #fff;
        font-size: 11px;
        text-transform: uppercase;
        padding: 10px 15px;
        vertical-align: middle;
    }

    tbody tr:nth-child(even) {

        background: #f0f0f2;
    }

    #CreationDate {

        font-family: Arial, Helvetica, sans-serif;
        color: #ff3300;
        font-size: 12px;
    }

    .StopStatus {

        color: #ff0000;
    }

    .RunningStatus {

        color: #008000;
    }

</style>
"@

        }

        Process {
        
            $Title = "<h1>Gladinet Support System Analysis</h1>"
            $ComputerName = "<h2>Computer Name: $env:computername</h2>"

            $ProductInfo = $Version | 
            ConvertTo-Html -Property 'ProductName', 'ProductVersion', 'InstallationPath', 'UpdateHost', 'gteamclientpath', 'FileSysDBPath' -Fragment -PreContent "<h2>Product Info</h2>"
            
            #Gets system .net version.
            $DonetVersion = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse |
            Get-ItemProperty -Name version -EA 0 | Where-Object { $_.PSChildName -Match 'Full' } | Select-Object PSChildName, version

            #The command below will get the Operating System information, convert the result to HTML code as a table and store it to a variable.
            $ComputerSystemInformation = Get-CimInstance -ClassName  Win32_ComputerSystem  | 
            Select-Object Model, Manufacturer, @{N = 'TotalRAM(GB)'; E = { $_.TotalPhysicalMemory / 1GB -as [int] } } | 
            ConvertTo-Html -Property Model, Manufacturer, 'TotalRAM(GB)' -Fragment -PreContent "<h2>Host System Information</h2>"
            
            $OSinfo = Get-CimInstance -Class Win32_OperatingSystem | Select-Object Caption, CSName, LocalDateTime, Version, OSArchitecture, SystemDrive, TotalVirtualMemorySize, FreePhysicalMemory,
            @{N = 'TotalMemoryInUse(GB)'; E = { [Math]::Round(($_.totalvirtualmemorysize - $_.freevirtualmemory) * 1KB / 1GB, 2 -as [int]) } },
            @{N = 'OperatingSystem'; E = { $_.Caption } },
            @{N = 'OSVersion'; E = { $_.Version } },
            @{N = 'Hostname'; E = { $_.CSName } },
            @{N = 'DotNetVersion'; E = { $DonetVersion.Version } } |
            ConvertTo-Html -Property Hostname, OperatingSystem, OSVersion, LocalDateTime, OSArchitecture, SystemDrive, DotNetVersion, 'TotalMemoryInUse(GB)' -Fragment -PreContent "<h2>Operating System</h2>"

            $VideoControllerInformation = Get-CimInstance -ClassName Win32_VideoController | Select-Object Description, DriverVersion, VideoModeDescription, VideoProcessor, MinRefreshRate, MaxRefreshRate |
            ConvertTo-Html -Property Description, DriverVersion, VideoModeDescription, VideoProcessor, MinRefreshRate, MaxRefreshRate -Fragment -PreContent "<h2>Graphic Card</h2>"
            #The command below will get the Processor information, convert the result to HTML code as table and store it to a variable.
            $ProcessInfo = Get-CimInstance -ClassName Win32_Processor  | ConvertTo-Html -Property  'Name', 'NumberofCores' -Fragment -PreContent "<h2>Processor</h2>"

            #The command below will get the details of Disk, convert the result to HTML code as table and store it to a variable.
            $DiscInfo = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | 
            Select-Object DeviceID, @{N = 'Size(GB)'; E = { [Math]::Round($_.Size / 1GB, 2 -as [int]) } }, 
            @{Name = 'FreeSpace(GB)'; E = { [Math]::Round($_.FreeSpace / 1GB -as [int]) } } |
            ConvertTo-Html -Property DeviceID, 'FreeSpace(GB)', 'Size(GB)' -Fragment -PreContent "<h2>Disk</h2>"

            #The command below will get first 10 services information, convert the result to HTML code as table and store it to a variable.
            $ServicesInfo = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -like 'GladFileMonSvc' -or 
                $_.Name -Like 'gladrmountsvc' -or
                $_.Name -like 'GladGroupSvc' -or
                $_.Name -like 'GCMon' -or
                $_.Name -like 'gladpostgresrv' } | Select-Object DisplayName, StartMode, State, Status, ExitCode | 
            ConvertTo-Html -Property DisplayName, StartMode, State, ExitCode -Fragment -as List  -PreContent "<h2>Services</h2>" 

            #Controls color for runnign services in the html report (Red for stop and Green for running).
            $ServicesInfo = $ServicesInfo -replace '<td>Running</td>', '<td class="RunningStatus">Running</td>'
            $ServicesInfo = $ServicesInfo -replace '<td>Stopped</td>', '<td class="StopStatus">Stopped</td>'

            Switch ($Product) {

                'CloudServer' {
                    
                    If ($IntervalProc) { 

                        $ProcessCount = 5
                        $Interval = 2
                    }

                    Else {

                        $ProcessCount = 1
                        $Interval = 1
                    }
                    $ProcessProps = @()

                    For ($Count = 0; $Count -lt $processCount; $Count++) {

                        $ProcessProps += Get-Process -Name W3wp -IncludeUserName | Select-Object `
                            Id, Handles, ProcessName, Username, 
                        @{Label = "Non-pagedMemory(K)"; Expression = { [int]($_.NPM / 1024) } },
                        @{Label = "PageableMemory(K)"; Expression = { [int]($_.PM / 1024) } },
                        @{Label = "WorkingSet(K)"; Expression = { [int]($_.WS / 1024) } },
                        @{Label = "VirtualMemory(M)"; Expression = { [int]($_.VM / 1MB) } },
                        @{Label = "CPU(s)"; Expression = { if ($_.CPU) { $_.CPU.ToString("N") } } } | 
                        ConvertTo-Html -Property 'Non-pagedMemory(K)', 'PageableMemory(K)', 'WorkingSet(K)', 'VirtualMemory(M)', 'CPU(s)', 'Id', 'Handles', 'ProcessName', 'username' -Fragment -PreContent "<h2>Process Info</h2>"
                        Start-Sleep -Seconds $Interval
                    }

                    $PerfLinks = @(

                        'http://localhost/storage/u.svc/proxyperf',
                        'http://localhost/namespace/n.svc/nodeperf'
                    )

                    foreach ($Link in $PerfLinks) { 

                        $filename = $Link.Split('/')[-1]; 
                        $Results = Invoke-RestMethod -Uri $Link; $Results.Save("$Outpath\$filename.xml") 
                    }

                    Break
                }

                'WindowsClient' { 

                    $ProductProcess = @(

                        'ClientShell',
                        'CoDesktopClient',
                        'GladFileMonSvc',
                        'gladrmounter'
                        
                    )
                    Break
                }

                'ServerAgent' { 

                    $ProductProcess = @(

                        'GladFileMonSvc',
                        'GladGroupSvc',
                        'gladrmounter',
                        'GServiceMain'
                    )
                    Break
                }
            }

            If (($Product -eq 'WindowsClient') -or ($Product -eq 'ServerAgent')) {

                $ProcessProps = Get-Process -Name $ProductProcess -ErrorAction SilentlyContinue

                If ($ProcessProps) {
            
                    $ProcessProps = $ProcessProps  | Select-Object Id, Handles, ProcessName, Username, 
                    @{Label = "Non-pagedMemory(K)"; Expression = { [int]($_.NPM / 1024) } },
                    @{Label = "PageableMemory(K)"; Expression = { [int]($_.PM / 1024) } },
                    @{Label = "WorkingSet(K)"; Expression = { [int]($_.WS / 1024) } },
                    @{Label = "VirtualMemory(M)"; Expression = { [int]($_.VM / 1MB) } },
                    @{Label = "CPU(s)"; Expression = { if ($_.CPU) { $_.CPU.ToString("N") } } } | 
                    ConvertTo-Html -Property 'Non-pagedMemory(K)', 'PageableMemory(K)', 'WorkingSet(K)', 'VirtualMemory(M)"', 'CPU(s)', 'Id', 'Handles', 'ProcessName' -Fragment -PreContent "<h2>Process Info</h2>"
                }
        
                Else {

                    Write-Output 'No Windows Client process found running.'
                }
            }
        }

        End {
        
            #The command below will combine all the information gathered into a single HTML report
            $Report = ConvertTo-HTML -Body "$Title $ComputerName $ProductInfo $ComputerSystemInformation $OSinfo $VideoControllerInformation $ProcessInfo $DiscInfo $ServicesInfo $ProcessProps" -Title "Gladinet System Report" -PostContent "<p>Creation Date: $(Get-Date)<p>" -Head $header

            #The command below will generate the report to an HTML file
            $Report | Out-File "$Outpath\GladinetSystemAnalysis.html"
        }
    }
    Function Start-CloudUpload {
        [CmdletBinding()]
        Param (
        
            [String[]]$Filepath, 
            [string]$SasToken, 
            [Parameter(
                Mandatory = $True)]
            $TicketNumber
        )

        Begin {

            $packages = Get-Item -Path "$filepath\GladinetTraceCollect-*"

            If (-Not($packages)) { 

                $CloudUploadProgressBox.AppendText("No packed content found:...`r`n")
                Return
            }

            Else { 

                $CloudUploadProgressBox.AppendText("Gladtrace Package found: Continuing...`r`n")
            }
            $UploadResult = [PSCustomObject]@{
                Arch             = '';
                AzDownloadResult = '';
                UploadResults    = '';
            }

            $OSArch = (Get-CimInstance -ClassName Win32_ComputerSystem).SystemType

            If ($OSArch -eq "X86-based PC") {
            
                $UploadResult.Arch = "X86-based PC"
                $AzCopylnk = 'https://aka.ms/downloadazcopy-v10-windows-32bit'
            }


            Else {

                $UploadResult.Arch = "x64-based PC"
                $AzCopylnk = 'https://aka.ms/downloadazcopy-v10-windows'
            }  

            $AzCopyPath = "$Env:USERPROFILE\Downloads\"

            If (-Not(Test-Path -Path "$AzCopyPath\Glad_AzCopy")) {

                $CloudUploadProgressBox.AppendText("Downloading AzCopy.zip...`r`n")
                Invoke-WebRequest -Uri $AzCopylnk -OutFile "$Env:USERPROFILE\Downloads\Glad_AzCopy.zip" -UseBasicParsing -ErrorAction Stop

                Add-type -AssemblyName "System.IO.Compression.FileSystem" 
                $DownloadPath = "$AzCopyPath\Glad_AzCopy.zip"

                $ExpandArchiveDestination = "$AzCopyPath\Glad_AzCopy"
                $CloudUploadProgressBox.AppendText("Extracting AzCopy.zip...`r`n")
                [System.IO.Compression.ZipFile]::ExtractToDirectory($DownloadPath, $ExpandArchiveDestination)

                Remove-Item -Path "$AzCopyPath\Glad_AzCopy.zip" -force
            }
        }
    
        Process {
        
            If ((Test-Path -Path "$AzCopyPath\Glad_AzCopy")) {

                $Azcopy_exe = Get-Item -Path "$AzCopyPath\Glad_AzCopy\AzCopy_*\Azcopy.exe"
                $UploadResult.AzDownloadResult = 'Sucess'
                $AzCopy_exe.FullName
                Push-Location -Path $AzCopy_exe.Directory

                    Foreach ($item in $packages) {
                    
                        $TicketNumberAppend = ($TicketNumber + '-' + $($item.name))
                        Write-Output $TicketNumberAppend
                        Rename-Item -LiteralPath $item.FullName -NewName "$TicketNumber-$($item.Name)"
                        $Item = Get-childitem -Path $AzCopyPath | Where-Object name -Match "$TicketNumber-$($item.Name)"
                        $CloudUploadProgressBox.AppendText('Uploading...')
                        & $Azcopy_exe.FullName copy $item.fullname $SASToken

                        If ($?) {

                            $CloudUploadProgressBox.text = "Upload successful.`r`n"
                        }

                        If (!$?) {

                            $CloudUploadProgressBox.text = "Upload failed.`r`n"
                            $CloudUploadProgressBox.text = $_
                        }
                    }
            }
        }
    
        End {
        
            Write-Output $UploadResult
            Pop-Location
            If (Test-Path -Path "$AzCopyPath\Glad_AzCopy" -ErrorAction SilentlyContinue) { 

                Remove-Item "$AzCopyPath\Glad_AzCopy" -force -Recurse
            }
        }
    }
    Function Connect-CloudAccount {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$UserName,

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$Password,

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$URL
        )
    
        Begin {
            $serviceURI = ("{0}/namespace/n.svc/japiusers/login" -f $URL)
            $Body = @{ 

                Username = $UserName;
                Password = $Password;
            } | ConvertTo-Json
        }
    
        Process {
        
            $Results = Invoke-WebRequest -Uri $serviceURI -ContentType 'application/json' -Body $Body -Method Post
            Write-Output ($Results.Content | ConvertFrom-Json).JAPIUserLoginResult
        }
    
        end {
        
        }
    }
    Function Select-Container {

        $ContainerSelectionform = New-Object System.Windows.Forms.Form
        $ContainerSelectionform.Text = 'Containers'
        $ContainerSelectionform.Size = New-Object System.Drawing.Size(300, 200)
        $ContainerSelectionform.StartPosition = 'CenterScreen'
        $ContainerSelectionform.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($GuiIcon)

        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Location = New-Object System.Drawing.Point(75, 120)
        $okButton.Size = New-Object System.Drawing.Size(75, 23)
        $okButton.Text = 'OK'
        $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $ContainerSelectionform.AcceptButton = $okButton
        $ContainerSelectionform.Controls.Add($okButton)

        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Location = New-Object System.Drawing.Point(150, 120)
        $cancelButton.Size = New-Object System.Drawing.Size(75, 23)
        $cancelButton.Text = 'Cancel'
        $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $ContainerSelectionform.CancelButton = $cancelButton
        $ContainerSelectionform.Controls.Add($cancelButton)

        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(10, 20)
        $label.Size = New-Object System.Drawing.Size(280, 20)
        $label.Text = 'Please select a container:'
        $ContainerSelectionform.Controls.Add($label)

        $listBox = New-Object System.Windows.Forms.ListBox
        $listBox.Location = New-Object System.Drawing.Point(10, 40)
        $listBox.Size = New-Object System.Drawing.Size(260, 20)
        $listBox.Height = 80

        $Containers = Get-CloudTenant -Token $Access.cookie -URL $AccessPoint
        Foreach ($Container in $Containers.orgnization) {
    
            [void] $listBox.Items.Add($Container)
        }

        $ContainerSelectionform.Controls.Add($listBox)

        $ContainerSelectionform.Topmost = $true

        $result = $ContainerSelectionform.ShowDialog()

        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            $Result = $listBox.SelectedItem
            Write-Output $result
        }
    }

    Function Set-WinDBGPostMortem {
        [Cmdletbinding()]
        Param (

            [Switch]$Enable
        )

        Begin {

            $WinDBGRegKeyPath = "HKLM:SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug"

        }
        Process {
        
            If ($Enable) {

                & "$Env:SystemDrive\Program Files (x86)\Windows Kits\10\Debuggers\x86\windbg.exe" /I
            }

            Else {

                If (Test-Path -Path $WinDBGRegKeyPath) {
                
                    Set-ItemProperty -Path $WinDBGRegKeyPath -Name Debugger -Value '"drwtsn32 -p %ld -e %ld -g"'
                }
            }
        }
        End {}
    }
    Function Get-CloudTenant {
        [CmdletBinding()]
        Param (
        
            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$Token, 

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$URL, 

            [String[]]$TenantName
        )
    
        Begin {
        
            $ServiceURL = ("{0}/namespace/n.svc/jsonenumtenants" -f $URL)

            $Headers = @{  
            
                "x-glad-token" = "$Token";
            } 
        }
    
        Process {

            Try { 

                $Result = Invoke-RestMethod -Uri $ServiceURL -Headers $Headers -Method Get -ContentType 'application/json' -ErrorAction Stop
                If ($TenantName) { 

                    Foreach ($Tenant in $Result.Tenants) { 

                        If ($Tenant.orgnization -eq $TenantName) { 

                            Write-Output 'Tenant Found'
                            Write-Output $Tenant
                            Break
                        }
                        Else {

                            Write-Output "tenant not found."
                        }
                    }
                }
            
                Else { 

                    Write-Output $Result.Tenants
                }
            }

            Catch { 

                $_ 
            }
        }
    
        End {
        
        }
    }
    Function Get-CloudNodePerformance {
        [CmdletBinding()]
        Param (
       
            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$Token, 

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$URL
        )
    
        Begin {
        
            $ServiceURL = ("{0}/namespace/n.svc/japiperfcounters" -f $URL)

            $Headers = @{ 

                "x-glad-token" = "$Token";
            } 
        }
    
        Process {
        
            $Results = Invoke-RestMethod -Uri $ServiceURL -Method Get -ContentType 'application/json' -Headers $Headers
            Write-Output $Results
        }
    
        End {
        
        }
    }
    Function Get-CloudHelloWorldStatus {
        [CmdletBinding()]
        Param (
        
            [String]$URL
        )
    
        Begin {
        
            $ServiceURL = ("{0}/namespace/n.svc/helloworld" -f $URL)
        }
    
        Process {
        
            $Results = Invoke-RestMethod -Uri $ServiceURL -Method Get -ContentType 'application/xml'
            $Results.string.'#text'
        }
    
        End {
        
        }
    }
    Function Get-CloudActiveUser {
        [CmdletBinding()]
        Param (

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$token,

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$TenantID,

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$URL
        )
    
        Begin {
        
            $ServiceURL = ("{0}/namespace/n.svc/japienumactiveuser" -f $URL)
            $Headers = @{  

                "x-glad-token" = "$Token";
            } 
            $Body = @{ 

                'DomainID' = "$TenantID";
            } | ConvertTo-Json
        }
    
        Process {
        
            $Results = Invoke-RestMethod -Uri $ServiceURL -Headers $Headers -Body $Body -ContentType 'application/json' -Method Post -ErrorAction Stop
            Write-Output ($Results.JAPIEnumActiveUserResult.UserList)
        }
    
        End {
        
        }
    }
    Function Get-CloudBrandedSettingsbyEmail {
        [CmdletBinding()]
        Param (

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$Token,

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$UserName,

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$URL
        )
    
        Begin {

            $serviceURI = ("{0}/namespace/n.svc/japigetbrandingsettingsbyemail" -f $URL)
        
            $Headers = @{ 

                "x-glad-token" = "$Token";
            } 

            $Body = @{

                "Email" = "Admin@local"
            } | ConvertTo-Json
        }
    
        Process {
        
            $Results = Invoke-WebRequest -Uri $serviceURI -ContentType 'application/json' -Headers $Headers -Body $Body -Method Post
            Write-Output $Results
        }
    
        End {
        
        }
    }
    Function Get-CloudClusterPerformance {
        [CmdletBinding()]
        Param (
        
            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$Token,

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$URL
        )
    
        Begin {

            $Headers = @{ 

                "x-glad-token" = "$Token";
            } 
        
            $serviceURI = ("{0}/namespace/n.svc/japiclusterperf" -f $URL)
        }
    
        Process {
       

            $Results = Invoke-WebRequest -Uri $serviceURI -Headers $Headers -ContentType 'application/json' -Method Get
            Write-Output ($Results | ConvertFrom-Json).JAPIGetClusterPerformanceResult.PerfMonCounters
        }
    
        End {
        
        }
    }
    Function Get-CloudDevice {
        [CmdletBinding()]
        param (
        
            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$Token, 

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$URL,

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$tenantID
        )
    
        begin {
        
            $ServiceURl = ('{0}/namespace/n.svc/japigettenantdevices' -f $URL)
            $header = @{ 

                'x-glad-token' = $Token;
            }

            $Body = @{ 

                'TenantId' = $tenantID;
            } | ConvertTo-Json
        }
    
        process {
        
            $Results = Invoke-RestMethod -Uri $ServiceURl -Headers $header -Body $Body -Method Post -ContentType 'application/json'
            Write-Output $Results.DeviceList
        }
    
        end {
        
        }
    }
    Function Get-CloudFolder {
        [CmdletBinding()]
        param (
     
            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$Token, 

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$URL,

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$tenantID, 

            [Parameter(ValueFromPipeline = $true)]
            [String]$FolderName
        )
    
    
        begin {
        
            $ServiceURl = ('{0}/namespace/n.svc/japigetteamfolders' -f $URL)

            $header = @{ 

                'x-glad-token' = $Token;
            }

            $Body = @{ 

                'TenantId' = $tenantID;
            } | ConvertTo-Json
        }
    
        process {
        
            $Results = Invoke-RestMethod -Uri $ServiceURl -Headers $header -Body $Body -Method Post -ContentType 'application/json'

            If ($FolderName) { 

                Foreach ($Folder in $Results.ShareList) { 

                    If ($Folder.ShareName -eq $FolderName) { 

                        Write-Output $Folder
                        Break
                    }

                    Else {

                        Continue
                    }
                }
            }
        
            Else { 

                Write-Output $Results.ShareList
            }

        }
    
        end {
        
        }
    }
    Function Get-CloudGroup {
        [CmdletBinding()]
        Param (
        
            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$Token, 

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$URL,

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [string]$TenantID, 

            [Parameter(ValueFromPipeline = $true)]
            [String[]]$GroupName
        )
    
        Begin {
        
            $ServiceURL = ("{0}/namespace/n.svc/japienumgroups" -f $URL)
            $Header = @{ 

                'x-glad-token' = $Token;
            }

            $Body = @{ 

                'TenantId' = $TenantID;
            } | ConvertTo-Json
        }
    
        Process {
        
            $Results = Invoke-RestMethod -Uri $ServiceURL -Headers $Header -Body $Body -Method Post -ContentType 'application/json'

            If ($GroupName) { 

                Foreach ($Group in $Results.Groups) { 

                    If ($Group.GroupName -eq $GroupName) { 

                        Write-Output $Group
                        Break
                    }

                    else {
                     
                        Continue
                    }
                }
            }

            Else {

                Write-Output $Results.Groups
            }
        }
    
        End {
        
        }
    }
    Function Get-CloudGroupMember {
        [CmdletBinding()]
        Param (
        
            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$Token, 

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$URL,

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [string]$TenantID, 

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$GroupID
        )
    
        Begin {
        
            $ServiceURL = ("{0}/namespace/n.svc/japitenants/$TenantID/groups/$GroupID/users" -f $URL)

            $Headers = @{ 

                "x-glad-token" = "$Token";
            } 
        }
    
        Process {
        
            $Results = Invoke-RestMethod -Uri $ServiceURL -Method Get -ContentType 'application/json' -Headers $Headers
            Write-Output $Results.JAPIGetGroupUsersResult
        }
    
        End {
        
        }
    }
    Function Get-CloudSystemStatus {
        [CmdletBinding()]
        Param (
        
            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$URL
        )
    
        Begin {
        
            $ServiceURL = ("{0}/namespace/n.svc/japisysscan" -f $URL)
        }
    
        process {
        
            $Result = Invoke-RestMethod -Uri $ServiceURL 
            Write-Output $Result.JAPISystemScanResult.InfoNodes
        }
    
        End {
        
        }
    }
    Function Get-CloudTenantDevice {
        [CmdletBinding()]
        Param (
        
            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$Token, 

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$URL, 

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$TenantID
        )
    
        Begin {
        
            $ServiceURL = ("{0}/namespace/n.svc/japigettenantdevices" -f $URL)

            $Headers = @{ 

                "x-glad-token" = "$Token";
            } 

            $Body = @{ 

                "TenantId" = $TenantID;
            } | ConvertTo-Json
        }
    
        Process {
        
            $Result = Invoke-RestMethod -Uri $ServiceURL -Headers $Headers -Body $Body -Method Post -ContentType 'application/json' -ErrorAction Stop
            Write-Output $Result.DeviceList
        }
    
        End {
        
        }
    }
    Function Get-CloudTenantGroupPolicy {
        [CmdletBinding()]
        Param (
        
            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$Token, 

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$URL, 

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$TenantID
        )
    
        begin {
        
            $ServiceURL = ("{0}/namespace/n.svc/japigettenantpolicy" -f $URL)

            $Headers = @{ 

                "x-glad-token" = "$Token";
            } 

            $Body = @{ 

                "TenantId" = $TenantID;
            } | ConvertTo-Json
        }
    
        process {
        
            $Result = Invoke-RestMethod -Uri $ServiceURL -Headers $Headers -Body $Body -Method Post -ContentType 'application/json' -ErrorAction Stop
            Write-Output $Result.MetaList
        }
    
        end {
        
        }
    }
    Function Get-CloudUserbyEmail {
        [CmdletBinding()]
        Param (

            [Parameter(Mandatory, 
                ValueFromPipelineByPropertyName = $true)]
            [String]$Email,

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$Token,

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$URL
        )
    
        Begin {
            $serviceURI = ("{0}/namespace/n.svc/japiqueryuserbyemail" -f $URL)

            $Headers = @{  
            
                "x-glad-token" = "$Token";
            } 

            $Body = @{
                "Email" = $Email;
            } | ConvertTo-Json
        }
    
        Process {
        
            $Results = Invoke-WebRequest -Uri $serviceURI -ContentType 'application/json' -Headers $Headers -Body $Body -Method Post
            Write-Output $Results
        }
    
        End {
        
        }
    }
    Function Get-CloudTenantBackendStorageConfig {
        [CmdletBinding()]
        Param (
        
            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$Token, 

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$URL,

            [Parameter(Mandatory, 
                ValueFromPipeline = $true)]
            [String]$tenantID
        )
    
        Begin {
        
            $ServiceURl = ('{0}/namespace/n.svc/japigettenantstorage' -f $URL)
            $header = @{ 

                'x-glad-token' = $Token;
            }

            $Body = @{ 

                'TenantId' = $tenantID;
            } | ConvertTo-Json
        }
    
        Process {
        
            $Result = Invoke-RestMethod -Uri $ServiceURl -Headers $header -Body $Body -Method Post -ContentType 'application/json'
            Write-Output (([xml]$Result.Context).StorageDescriptor)
        }
    
        End {
        
        }
    }

    $Script:Version = Get-GladVersion
    $MainScreen = New-Object -TypeName System.Windows.Forms.form
    $Script:GuiIcon = "$($Version.InstallationPath)\brand.ico"
    $Script:AccessPoint = 'http://localhost'
    $LegacyCSDefaultInstallationPath = "${Env:ProgramFiles(x86)}\Gladinet Cloud Enterprise\brand.ico"
    $LegacyServerAgentDefaultInstallationPathIcon = "$Env:ProgramFiles\Gladinet\Cloud Server Agent\3color-gateway.ico"

    If (($Version.InstallationPath)) { 

        If ($Version.ProductName -eq 'CloudServer' -and (Test-Path -Path $Version.InstallationPath -ErrorAction SilentlyContinue )) {

            $MainScreen = New-Object -TypeName System.Windows.Forms.form
            $MainScreen.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($GuiIcon)
        }

        Elseif ($Version.productname -eq 'WindowsClient' -and (Test-Path -Path $Version.InstallationPath -ErrorAction SilentlyContinue)) {

            $MainScreen = New-Object -TypeName System.Windows.Forms.form
            $MainScreen.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($GuiIcon)
        }

        Elseif ($Version.productname -eq 'ServerAgent' -and (Test-Path -Path $Version.InstallationPath -ErrorAction SilentlyContinue)) {

            $MainScreen = New-Object -TypeName System.Windows.Forms.form
            If (Test-Path -Path $LegacyServerAgentDefaultInstallationPathIcon -ErrorAction SilentlyContinue) { 

                $MainScreen.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($LegacyServerAgentDefaultInstallationPathIcon)
            }
            
            Else { 

                $MainScreen.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($GuiIcon)
            }
        }

        #End of Icons.
    }

    ElseIf (Test-Path -Path $LegacyCSDefaultInstallationPath) {

        $GuiIcon = $LegacyCSDefaultInstallationPath
        $MainScreen = New-Object -TypeName System.Windows.Forms.form
        $MainScreen.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($GuiIcon)
    }
    #Controls the icons for the GUI based on installed solution.
    Else {

        $MainScreen = New-Object -TypeName System.Windows.Forms.form
    }

    #Generates the Main screen.
    $MainScreen.text = 'Gladtrace Collect'
    $MainScreen.size = New-Object -TypeName System.Drawing.Size(600, 335)
    $MainScreen.Top = $True
    $MainScreen.FormBorderStyle = "Fixed3D"
    $MainScreen.StartPosition = 'CenterScreen'

    #Generates the tab control.
    $TabControl = New-Object -TypeName System.Windows.Forms.TabControl
    $TabControl.DataBindings.DefaultDataSourceUpdateMode = 0
    $TabControl.Location = New-Object -TypeName System.Drawing.Point(0, 0)
    $TabControl.Size = New-Object -TypeName System.Drawing.Size(600, 300)
    $TabControl.Name = 'Tab Control'
    $MainScreen.Controls.Add($TabControl)

    #Box used to write verbose inforamation to Gladtrace prompt. 
    $ProgressBox = New-Object -TypeName System.Windows.Forms.TextBox
    $ProgressBox.Location = New-Object System.Drawing.point(280, 20)
    $ProgressBox.Size = New-object -TypeName System.Drawing.Size(285, 230)
    $ProgressBox.Multiline = $true
    $ProgressBox.scrollbars = "Vertical"
    $ProgressBox.WordWrap = $true
    $ProgressBox.BackColor = '#E6EDF0'
    #$MainScreen.Controls.Add($ProgressBox)

    $WinDbgProgressBox = New-Object -TypeName System.Windows.Forms.TextBox
    $WinDbgProgressBox.Location = New-Object System.Drawing.point(280, 20)
    $WinDbgProgressBox.Size = New-object -TypeName System.Drawing.Size(285, 230)
    $WinDbgProgressBox.Multiline = $true
    $WinDbgProgressBox.scrollbars = "Vertical"
    $WinDbgProgressBox.WordWrap = $true
    $WinDbgProgressBox.BackColor = '#E6EDF0'
    
    #Tab for Debug Trace
    $DebugTraceTabPage = New-Object -TypeName System.Windows.Forms.TabPage
    $DebugTraceTabPage.BackColor = '#E0F3F6'
    $DebugTraceTabPage.Text = 'DebugView'
    $DebugTraceTabPage.Size = New-Object -TypeName System.Drawing.Size(300, 300)
    
    $TabControl.Controls.Add($DebugTraceTabPage)
    #Adds DebugView Progress box.
    $DebugTraceTabPage.Controls.Add($ProgressBox)
    
    #WinDBG tab.
    $WinDBGTabPage = New-Object -TypeName System.Windows.Forms.TabPage
    $WinDBGTabPage.Text = 'WinDbg'
    $WinDBGTabPage.BackColor = '#E0F3F6'
    $TabControl.Controls.Add($WinDBGTabPage)

    #Adds WinDBGProgress box to the WinDBG tab Control.
    $WinDBGTabPage.Controls.Add($WinDbgProgressBox)

    #Package Upload tab
    $PackageUploadTabPage = New-Object -TypeName System.Windows.Forms.TabPage
    $PackageUploadTabPage.BackColor = '#E0F3F6'
    $PackageUploadTabPage.Text = 'Upload'
    If (-Not($SasToken)) {

        $PackageUploadTabPage.Enabled = $false
    }
    $TabControl.Controls.Add($PackageUploadTabPage)

    #Tab for Sign in
    $SignInTabPage = New-Object -TypeName System.Windows.Forms.TabPage
    $SignInTabPage.BackColor = '#E0F3F6'
    $SignInTabPage.Text = 'Report Generator'
    $SignInTabPage.Size = New-Object -TypeName System.Drawing.Size(300, 300)

    If ($Version.ProductName -eq 'CloudServer') {

        $TabControl.Controls.Add($SignInTabPage)
    }

    #Report Generator tab <Start>.
    $ReportGeneratorTabPage = New-Object -TypeName System.Windows.Forms.TabPage
    $ReportGeneratorTabPage.Text = 'Report Generator'
    $ReportGeneratorTabPage.BackColor = '#E0F3F6'

    $CloudFolderCheckBox = New-Object -TypeName System.Windows.Forms.CheckBox
    $CloudFolderCheckBox.Location = New-Object -TypeName System.Drawing.Point(20, 10)
    $CloudFolderCheckBox.Size = New-Object -TypeName System.Drawing.Size(100, 30)
    $CloudFolderCheckBox.Text = "Cloud Folder"
    $ReportGeneratorTabPage.Controls.Add($CloudFolderCheckBox)

    $CloudFolderComboBox = New-Object -TypeName System.Windows.Forms.ComboBox
    $CloudFolderComboBox.Location = New-Object -TypeName System.Drawing.Point(150, 15)
    $CloudFolderComboBox.Size = New-Object -TypeName System.Drawing.Size(180, 30)

    $GroupsExportCheckBox = New-Object -TypeName System.Windows.Forms.CheckBox
    $GroupsExportCheckBox.Location = New-Object -TypeName System.Drawing.Point(20, 40)
    $GroupsExportCheckBox.Size = New-Object -TypeName System.Drawing.Size(100, 30)
    $GroupsExportCheckBox.Text = "Groups"
    
    $GroupsComboBox = New-Object -TypeName System.Windows.Forms.ComboBox
    $GroupsComboBox.Location = New-Object -TypeName System.Drawing.Point(150, 45)
    $GroupsComboBox.Size = New-Object -TypeName System.Drawing.Size(180, 30)
    $ReportGeneratorTabPage.Controls.Add($GroupsComboBox)

    $TenantDevicesExportCheckBox = New-Object -TypeName System.Windows.Forms.CheckBox
    $TenantDevicesExportCheckBox.Location = New-Object -TypeName System.Drawing.Point(20, 70)
    $TenantDevicesExportCheckBox.Size = New-Object -TypeName System.Drawing.Size(105, 30)
    $TenantDevicesExportCheckBox.Text = "Tenant Devices"

    $TenantDevicesComboBox = New-Object -TypeName System.Windows.Forms.ComboBox
    $TenantDevicesComboBox.Location = New-Object -TypeName System.Drawing.Point(150, 75)
    $TenantDevicesComboBox.Size = New-Object -TypeName System.Drawing.Size(180, 30)
    $ReportGeneratorTabPage.Controls.Add($TenantDevicesComboBox)

    $SystemScanExportCheckBox = New-Object -TypeName System.Windows.Forms.CheckBox
    $SystemScanExportCheckBox.Location = New-Object -TypeName System.Drawing.Point(20, 105)
    $SystemScanExportCheckBox.Size = New-Object -TypeName System.Drawing.Size(200, 30)
    $SystemScanExportCheckBox.Text = "System Status"
    $ReportGeneratorTabPage.Controls.Add($SystemScanExportCheckBox)

    $ActiveUsersExportCheckBox = New-Object -TypeName System.Windows.Forms.CheckBox
    $ActiveUsersExportCheckBox.Location = New-Object -TypeName System.Drawing.Point(20, 130)
    $ActiveUsersExportCheckBox.Size = New-Object -TypeName System.Drawing.Size(200, 30)
    $ActiveUsersExportCheckBox.Text = "Active Users"
    $ReportGeneratorTabPage.Controls.Add($ActiveUsersExportCheckBox)

    $GroupPolicyExportCheckBox = New-Object -TypeName System.Windows.Forms.CheckBox
    $GroupPolicyExportCheckBox.Location = New-Object -TypeName System.Drawing.Point(20, 155)
    $GroupPolicyExportCheckBox.Size = New-Object -TypeName System.Drawing.Size(200, 30)
    $GroupPolicyExportCheckBox.Text = "Group Policy"
    $ReportGeneratorTabPage.Controls.Add($GroupPolicyExportCheckBox)

    $SystemPerformanceExportCheckBox = New-Object -TypeName System.Windows.Forms.CheckBox
    $SystemPerformanceExportCheckBox.Location = New-Object -TypeName System.Drawing.Point(20, 180)
    $SystemPerformanceExportCheckBox.Size = New-Object -TypeName System.Drawing.Size(200, 30)
    $SystemPerformanceExportCheckBox.Text = "System Performance"
    $ReportGeneratorTabPage.Controls.Add($SystemPerformanceExportCheckBox)

    $HelloWorldCheckbox = New-Object -TypeName System.Windows.Forms.CheckBox
    $HelloWorldCheckbox.Location = New-Object -TypeName System.Drawing.Point(20, 205)
    $HelloWorldCheckbox.Size = New-Object -TypeName System.Drawing.Size(200, 30)
    $HelloWorldCheckbox.Text = "Hello world check"
    $ReportGeneratorTabPage.Controls.Add($HelloWorldCheckbox)

    $TenantBackendStorageCheckBox = New-Object -TypeName System.Windows.Forms.CheckBox
    $TenantBackendStorageCheckBox.Location = New-Object -TypeName System.Drawing.Point(20, 230)
    $TenantBackendStorageCheckBox.Size = New-Object -TypeName System.Drawing.Size(200, 30)
    $TenantBackendStorageCheckBox.Text = "Tenant Storage Configuration"
    $ReportGeneratorTabPage.Controls.Add($TenantBackendStorageCheckBox)
    
    #Upload Tab label
    $TicketNumLabel = New-Object -TypeName System.Windows.Forms.Label
    $TicketNumLabel.Location = New-Object -TypeName System.Drawing.Point(20, 82)
    $TicketNumLabel.size = New-Object -TypeName System.Drawing.Size(90, 20)
    $TicketNumLabel.text = "Ticket Number:"
    If ($SasToken) {

        $PackageUploadTabPage.Controls.Add($TicketNumLabel) 
    }
        
    #Upload Tab box
    $TicketNumbox = New-Object -TypeName System.Windows.Forms.Textbox
    $TicketNumbox.Location = New-Object -TypeName System.Drawing.Point(110, 80)
    $TicketNumbox.size = New-Object -TypeName System.Drawing.Size(120, 20)
    If ($SasToken) {

        $PackageUploadTabPage.Controls.Add($TicketNumbox)
    }

    $CloudUploadProgressBox = New-Object -TypeName System.Windows.Forms.TextBox
    $CloudUploadProgressBox.Location = New-Object System.Drawing.point(280, 20)
    $CloudUploadProgressBox.Size = New-object -TypeName System.Drawing.Size(285, 230)
    $CloudUploadProgressBox.Multiline = $true
    $CloudUploadProgressBox.scrollbars = "Vertical"
    $CloudUploadProgressBox.WordWrap = $true
    $CloudUploadProgressBox.BackColor = '#E6EDF0'
    If ($SasToken) {

        $PackageUploadTabPage.Controls.Add($CloudUploadProgressBox) 
    }
    
    #Upload Tab button
    $TicketNumButtonUpload = New-Object -TypeName System.Windows.Forms.Button
    $TicketNumButtonUpload.Location = New-Object -TypeName System.Drawing.Point(100, 170)
    $TicketNumButtonUpload.size = New-Object -TypeName System.Drawing.Size(100, 30)
    $TicketNumButtonUpload.Text = "Upload"
    If ($SasToken) {

        $PackageUploadTabPage.Controls.Add($TicketNumButtonUpload)
    }

    #Instructions on how to enable Upload.
    $ToUseInstructionsLabel = New-Object -TypeName System.Windows.Forms.Label
    $ToUseInstructionsLabel.Location = New-Object -TypeName System.Drawing.Point(35, 125)
    $ToUseInstructionsLabel.Size = New-Object -TypeName System.Drawing.Size(500, 20)
    $ToUseInstructionsLabel.Text = "To enable cloud upload, provide an Azure blob SAS token with 'Create' rights on line 16 of the code"
    If (-Not($SasToken)) {

        $PackageUploadTabPage.Controls.Add($ToUseInstructionsLabel)
    }
    
    $UsernameLabel = New-Object -TypeName System.Windows.Forms.Label
    $UsernameLabel.Location = New-Object -TypeName System.Drawing.Point(60, 82)
    $UsernameLabel.Size = New-Object -TypeName System.Drawing.Size(160, 20)
    $UsernameLabel.Text = 'Cluster Administrator Email:'
    $SignInTabPage.Controls.Add($UsernameLabel)

    $UsernameTxtBox = New-Object -TypeName System.Windows.Forms.TextBox
    $UsernameTxtBox.Location = New-Object -TypeName System.Drawing.Point(220, 80)
    $UsernameTxtBox.Size = New-Object -TypeName System.Drawing.Size(140, 20)
    $SignInTabPage.Controls.Add($UsernameTxtBox)

    $PasswordLabel = New-Object -TypeName System.Windows.Forms.Label
    $PasswordLabel.Location = New-Object -TypeName System.Drawing.Point(150, 112)
    $PasswordLabel.Size = New-Object -TypeName System.Drawing.Size(70, 20)
    $PasswordLabel.Text = 'Password:'
    $SignInTabPage.Controls.Add($PasswordLabel)

    $PasswordTxtBox = New-Object -TypeName System.Windows.Forms.MaskedTextBox
    $PasswordTxtBox.Location = New-Object -TypeName System.Drawing.Point(220, 110)
    $PasswordTxtBox.Size = New-Object -TypeName System.Drawing.Size(140, 20)
    $PasswordTxtBox.PasswordChar = "*"
    $SignInTabPage.Controls.Add($PasswordTxtBox)

    $WrongPasswordLabel = New-Object -TypeName System.Windows.Forms.Label
    $WrongPasswordLabel.Location = New-Object -TypeName System.Drawing.Point(215, 180)
    $WrongPasswordLabel.Size = New-Object -TypeName System.Drawing.Size(180, 20)
    $WrongPasswordLabel.Visible = 'True'
    $SignInTabPage.Controls.Add($WrongPasswordLabel)

    #Sign in.
    $SigninButton = New-Object -TypeName System.Windows.Forms.Button
    $SigninButton.Location = New-Object -TypeName System.Drawing.Point(240, 140)
    $SigninButton.Size = New-Object -TypeName System.Drawing.Size(100, 30)
    $SigninButton.Text = 'Sign in'
    $SignInTabPage.Controls.Add($SigninButton)

    #Checkfox for screenshots.
    $ScreenShotsCheckbox = New-Object -TypeName System.Windows.Forms.CheckBox
    $ScreenShotsCheckbox.Text = 'Include screenshots'
    $ScreenShotsCheckbox.Location = New-Object -TypeName System.Drawing.Point(19, 75)
    $ScreenShotsCheckbox.Size = New-Object -TypeName System.Drawing.Size(150, 20)
    $ScreenShotsCheckbox.Checked = $true
    $DebugTraceTabPage.Controls.Add($ScreenShotsCheckbox)
    
    #Capture button.
    $CaptureButton = New-Object -TypeName System.Windows.Forms.Button
    $CaptureButton.Location = New-Object -TypeName System.Drawing.Point(20, 25)
    $CaptureButton.Size = New-Object -TypeName System.Drawing.Size(240, 50)
    $CaptureButton.Text = 'Capture'
    $DebugTraceTabPage.Controls.Add($CaptureButton)

    #Clear button.
    $ClearButton = New-Object -TypeName System.Windows.Forms.Button
    $ClearButton.Location = New-Object -TypeName System.Drawing.Point(20, 115)
    $ClearButton.Size = New-Object -TypeName System.Drawing.Size(240, 50)
    $ClearButton.Text = 'Clear traces'
    $DebugTraceTabPage.Controls.Add($ClearButton)
        
    #Checkbox for collecting FileSysDb.
    $FileSysDBCheckbox = New-Object -TypeName System.Windows.Forms.CheckBox
    $FileSysDBCheckbox.Text = 'Collect fileSysDB'
    $FileSysDBCheckbox.Location = New-Object -TypeName System.Drawing.Point(20, 250)
    $FileSysDBCheckbox.Size = New-Object -TypeName System.Drawing.Size(150, 20)
    
    If ($Version.ProductName -eq 'CloudServer') {

        $FileSysDBCheckbox.Visible = $false
    }
    $DebugTraceTabPage.Controls.Add($FileSysDBCheckbox)

    #Pack button.
    $PackButton = New-Object -TypeName System.Windows.Forms.Button
    $PackButton.Location = New-Object -TypeName System.Drawing.Point(20, 200)
    $PackButton.Size = New-Object -TypeName System.Drawing.Size(240, 50)
    $PackButton.Text = 'Pack'
    $DebugTraceTabPage.Controls.Add($PackButton)
        
    #Download Windbg Button
    $DownloadWinDdbgButton = New-Object -TypeName System.Windows.Forms.Button
    $DownloadWinDdbgButton.Location = New-Object -TypeName System.Drawing.Point(20, 20)
    $DownloadWinDdbgButton.Size = New-Object -TypeName System.Drawing.Size(240, 40)
    $DownloadWinDdbgButton.Text = 'Install'
    $WinDBGTabPage.Controls.Add($DownloadWinDdbgButton)

    #Uninstall WinDbg Button
    $UninstallWinDdbgButton = New-Object -TypeName System.Windows.Forms.Button
    $UninstallWinDdbgButton.Location = New-Object -TypeName System.Drawing.Point(20, 65)
    $UninstallWinDdbgButton.Size = New-Object -TypeName System.Drawing.Size(240, 40)
    $UninstallWinDdbgButton.Text = 'Uninstall'
    $WinDBGTabPage.Controls.Add($UninstallWinDdbgButton)

    #Download button for downloading symbols files. 
    $DownloadSymbolsButton = New-Object -TypeName System.Windows.Forms.Button
    $DownloadSymbolsButton.Location = New-Object -TypeName System.Drawing.Point(20, 110)
    $DownloadSymbolsButton.Size = New-Object -TypeName System.Drawing.Size(240, 40)
    $DownloadSymbolsButton.Text = 'Symbols'
    $WinDBGTabPage.Controls.Add($DownloadSymbolsButton)

    #Button for showing WinDBG commands in the Gladtrace prompt. 
    $ShowWinDBGInstructions = New-Object -TypeName System.Windows.Forms.Button
    $ShowWinDBGInstructions.Location = New-Object -TypeName System.Drawing.Point(20, 155)
    $ShowWinDBGInstructions.Size = New-Object -TypeName System.Drawing.Size(240, 40)
    $ShowWinDBGInstructions.Text = 'Help'
    $WinDBGTabPage.Controls.Add($ShowWinDBGInstructions )

    $EnableDisablePostMortem = New-Object -TypeName System.Windows.Forms.Button
    $EnableDisablePostMortem.Location = New-Object -TypeName System.Drawing.Point(20, 200)
    $EnableDisablePostMortem.Size = New-Object -TypeName System.Drawing.Size(240, 40)

    #Registry entry for windbg postmortem
    $Script:WinDBGRegKeyPath = "HKLM:SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug"
    $Props = Get-ItemProperty -Path $WinDBGRegKeyPath
    If ($Props.Debugger -match "drwtsn32 -p %ld -e %ld -g") {
     
        $EnableDisablePostMortem.Text = 'Enable postmortem'
    }

    Else {

        $EnableDisablePostMortem.Text = 'Disable postmortem'
    }

    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    If ((New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) -and ($Version.ProductName -ne 'CloudServer')) {

        $WinDBGTabPage.Controls.Add($EnableDisablePostMortem )
    }

    #Event handlers
    $CaptureButton.Add_Click( {


            If ($ScreenShotsCheckbox.Checked) {

                $CaptureButton.Text = 'Running'
                GladTrace -Collect -StepsRecorder
                $CaptureButton.Text = 'Capture'
            }

            Else {
            
                GladTrace -Collect
            }
        })

    $ClearButton.Add_Click( {

            Clear-GladTraceLogs
        })

    $PackButton.Add_Click( {

            If (-Not(Test-Path -Path "$Outpath\GladinetTraceCollect")) { 

                New-Item -Path "$Env:USERPROFILE\downloads" -Name GladinetTraceCollect -ItemType Directory -Force
            }

            If ($Access.Cookie) { 

                If ($Containerid) { 

                    If ($TenantBackendStorageCheckBox.Checked -eq 'True') { 

                        Get-CloudTenantBackendStorageConfig -token $Access.cookie -URL $AccessPoint -tenantID $Script:Containerid >> "$Outpath\TenantStorageConfig.txt"
                    }

                    If ($SystemScanExportCheckBox.Checked -eq 'True') { 

                        Get-CloudSystemStatus -URL $AccessPoint >> "$Outpath\SystemStatus.txt"
                    }

                    If ($ActiveUsersExportCheckBox.Checked -eq 'True') { 

                        Get-CloudActiveUser -token $Access.cookie -TenantID $Script:Containerid  -URL $AccessPoint >> "$Outpath\ActiveUsers.txt"
                    }

                    If ($GroupPolicyExportCheckBox.Checked -eq 'True') { 

                        $GroupPolicyConfig = Get-CloudTenantGroupPolicy -URL $AccessPoint -Token $Access.cookie -TenantID $Script:Containerid  
                        $GroupPolicyConfig >> "$Outpath\GroupPolicyConfig.txt"
                    }

                    If ($SystemPerformanceExportCheckBox.Checked -eq 'True') { 

                        Get-CloudClusterPerformance -URL $AccessPoint -Token $Access.cookie >> "$Outpath\ClusterPerformance.txt"
                    }

                    If ($HelloWorldCheckbox.Checked -eq 'True') { 

                        Get-CloudHelloWorldStatus -URL $AccessPoint >> "$Outpath\HelloWorld.txt"
                
                    }

                    If (($CloudFolderCheckBox.Checked -eq 'True') -and ($CloudFolderComboBox.SelectedItem)) {

                        $CloudFolder | Where-Object { $_.ShareName -eq $CloudFolderComboBox.SelectedItem } >> "$Outpath\CloudFolderConfigurationExport.txt"
                    }

                    If (($GroupsExportCheckBox.Checked -eq 'True') -and ($GroupsComboBox.SelectedItem)) {

                        $SelectedGroup = $Groups | Where-Object { $_.GroupName -eq $GroupsComboBox.SelectedItem }
                        $SelectedGroup >> "$Outpath\GroupConfigurationExport.txt"
                        $GroupMembers = Get-CloudGroupMember -Token $Access.cookie -URL $AccessPoint -TenantID $Script:Containerid -GroupID $SelectedGroup.GroupID 
                        $GroupMembers.Users | Out-String >> "$Outpath\GroupConfigurationExport.txt"
                    }

                    If (($TenantDevicesExportCheckBox.Checked -eq 'True') -and ($TenantDevicesComboBox.SelectedItem)) {

                        $TenantDevices | Where-Object { $_.HostName -eq $TenantDevicesComboBox.SelectedItem.Split(',')[1] -and `
                                $TenantDevicesComboBox.SelectedItem.Split(',')[0] -eq $_.UserEmail } >> "$Outpath\TenantDeviceExport.txt"
                    }
                }
            }

            If ($FileSysDBCheckbox.Checked) {
            
                $PackButton.Text = 'Packing Up'
                Gladtrace -Pack -FileSysDB

                $PackButton.Text = 'Finished'
                $PackButton.Text = 'Pack'
            }

            Else {
                
                $PackButton.Text = 'Packing Up'
                Gladtrace -Pack 
                $PackButton.Text = 'Finished'
                $PackButton.Text = 'Pack'
            }
        })

    $DownloadWinDdbgButton.Add_Click( { 
        
            $DownloadWinDdbgButton.Text = 'Downloading WinDBG'
            GladTrace -WindbgInstall
            $DownloadWinDdbgButton.Text = 'Finished' 
            $DownloadWinDdbgButton.Text = 'Download'
            New-WinDdbgInstructions
        })

    $UninstallWinDdbgButton.Add_Click( { 
    
            GladTrace -WindbgUninstall 
        })

    $DownloadSymbolsButton.Add_Click( { 
        
            $DownloadSymbolsButton.Text = 'Downloading symbol files..'    
            GladTrace -DownloadpdbFiles 
            $DownloadSymbolsButton.Text = 'Finished'
            Start-Sleep 2
            $DownloadSymbolsButton.Text = 'Symbols'
            New-WinDdbgInstructions
        })

    $ShowWinDBGInstructions.Add_Click( {

            New-WinDdbgInstructions
        })

    $EnableDisablePostMortem.Add_Click( {

            $Props = Get-ItemProperty -Path $WinDBGRegKeyPath
            If ($Props.Debugger -match "drwtsn32 -p %ld -e %ld -g") {
     
                Set-WinDBGPostMortem -Enable
                $EnableDisablePostMortem.Text = 'Disable postmortem'
            }

            Else {

                Set-WinDBGPostMortem -Enable:$false
                $EnableDisablePostMortem.Text = 'Enable postmortem'
            }
        })

    $TicketNumButtonUpload.Add_Click( {

            Start-CloudUpload -Filepath "$Env:Userprofile\Downloads" -TicketNumber $TicketNumbox.text -SasToken $SasToken
        })

    $SigninButton.Add_Click( {

            $Script:Access = $Null
            $Script:Access = Connect-CloudAccount -Username $UsernameTxtBox.Text -Password $PasswordTxtBox.Text -URL $AccessPoint

            If ($Access.success -eq 'True') {

                $WrongPasswordLabel.Text = '     Sign in sucessful'
                $Script:Containers = Get-CloudTenant -Token $Access.cookie -URL $AccessPoint

                If ($Containers) {

                    $ContainerSelection = Select-Container
                }

                $Script:Containerid = (Get-CloudTenant -token $access.Cookie -url $AccessPoint -TenantName $ContainerSelection).DomainId

                If ($Containerid) { 

                    #Enum cloud folders in GUI
                    $Script:CloudFolder = Get-CloudFolder -Token $Access.Cookie -URL $AccessPoint -tenantID $Containerid
                    Foreach ($Folder in $CloudFolder) { 

                        [void]$CloudFolderComboBox.Items.Add($Folder.ShareName)
                    }

                    #Enum Groups in GUI
                    $Script:Groups = Get-CloudGroup -URL $AccessPoint -Token $Access.Cookie -TenantID $Containerid
                    Foreach ($Group in $Groups) { 

                        [void]$GroupsComboBox.Items.Add($Group.GroupName)
                    }

                    #Enum Tenant Devices
                    $Script:TenantDevices = Get-CloudDevice -URL $AccessPoint -Token $Access.cookie -tenantID $Containerid
                    Foreach ($Device in $TenantDevices) { 

                        [void]$TenantDevicesComboBox.Items.Add("$($Device.UserEmail),$($Device.Hostname)")
                    }
                }

                $ReportGeneratorTabPage.Controls.Add($CloudFolderComboBox)
                $ReportGeneratorTabPage.Controls.Add($GroupsExportCheckBox)
                $ReportGeneratorTabPage.Controls.Add($TenantDevicesExportCheckBox)
                $TabControl.Controls.Add($ReportGeneratorTabPage)
                $SignInTabPage.Enabled = $false
                $TabControl.TabPages.Remove($SignInTabPage)
            }

            Else {
                $WrongPasswordLabel.ForeColor = 'Red'
                $WrongPasswordLabel.Text = 'Wrong Username/Password.'
            }
        })

    [void]$MainScreen.ShowDialog()
}
GladTraceToolUI 


