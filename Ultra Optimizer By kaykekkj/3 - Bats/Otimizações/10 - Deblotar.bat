��&cls
ÿþ&cls
@echo off
color 03
title by kaykekkj
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Appinfo" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Winmgmt" /v "Start" /t REG_DWORD /d "2" /f
sc config winmgmt start= auto
net start winmgmt
powershell -command "Get-AppxPackage *Microsoft.WindowsNotepad* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.People* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.549981C3F5F10* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.Windows.CloudExperienceHost* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.Windows.PeopleExperienceHost* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.XboxGameOverlay* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.XboxGamingOverlay* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.XboxIdentityProvider* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.XboxGameCallableUI* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.GamingServices* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.MicrosoftEdgeBeta* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.MicrosoftEdgeStable* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.MicrosoftEdgeDevToolsClient* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.Windows.ShellExperienceHost* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.Windows.StartMenuExperienceHost* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Client-ProjFS* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *TelnetClient* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *TFTP* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *TIFFIFilter* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *NetFx4-AdvSrvs* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *WCF-Services45* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.Todos* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.SecHealthUI* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.GamingApp* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.BingWeather* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.ZuneMusic* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.ZuneVideo* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.WindowsAlarms* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.WindowsMaps* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.YourPhone* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.WindowsNotepad* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.GetHelp* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *MicrosoftTeams* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.BingSearch* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.ScreenSketch* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.PowerAutomateDesktop* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.Getstarted* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.WindowsCalculator* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.WindowsCamera* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.BingNews* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.Xbox.TCUI* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Clipchamp.Clipchamp* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Clipchamp* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.OutlookForWindows* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.DolbyAudioExtensions* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *microsoft.windowscommunicationsapps* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.WindowsTerminal* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.Windows.NarratorQuickStart* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.Windows.ContentDeliveryManager* | Remove-AppxPackage"
powershell -command "Get-AppxPackage *Microsoft.Win32WebViewHost* | Remove-AppxPackage"


rem Uninstalls "Remote Desktop Connection" program
mstsc /uninstall

rem Disable "Application Information" service
net stop Appinfo
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Appinfo" /v "Start" /t REG_DWORD /d "4" /f

rem Disable and stop WMI

reg add "HKLM\SYSTEM\CurrentControlSet\Services\Winmgmt" /v "Start" /t REG_DWORD /d "4" /f
sc config winmgmt start= disabled
net stop winmgmt

PAUSE
