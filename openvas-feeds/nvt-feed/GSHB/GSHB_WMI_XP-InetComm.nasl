# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96038");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Checks XP Internetcommunication of some Programs - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"The script Checks XP Internetcommunication of some Programs:

  * Internet Explorer

  * Windows Media Player

  * Windows Messenger

  * Windows Zeitdienst

  * Hilfe- und Supportcenter

  * Windows Update

  * Gerätemanager

  * Windows Aktivierung und Registrierung

  * Aktualisierung der Stammzertifikate

  * Ereignisanzeige

  * Webdienst Assoziation

  * Fehlerberichterstattung");

  exit(0);
}

include("smb_nt.inc");

host    = get_host_ip();
usrname = kb_smb_login();
domain  = kb_smb_domain();
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd = kb_smb_password();

OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");

if(!OSVER || OSVER >< "none"){
  set_kb_item(name:"WMI/XP-InetComm", value:"error");
  set_kb_item(name:"WMI/XP-InetComm/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

handle = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/XP-InetComm", value:"error");
  set_kb_item(name:"WMI/XP-InetComm/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  exit(0);
}

NoUpdateCheckKEY = wmi_reg_enum_value(wmi_handle:handle, key:"Software\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions");
NoUpdateCheckKEY = tolower(NoUpdateCheckKEY);
if ("noupdatecheck" >< NoUpdateCheckKEY)
{
  NoUpdateCheck = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions", val_name:"NoUpdateCheck");
}
else NoUpdateCheck = "None";

PreventAutoRunKEY = wmi_reg_enum_value(wmi_handle:handle, key:"Software\Policies\Microsoft\Messenger\Client");
PreventAutoRunKEY = tolower(PreventAutoRunKEY);
if ("preventautorun" >< PreventAutoRunKEY)
{
  PreventAutoRun = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Policies\Microsoft\Messenger\Client", val_name:"PreventAutoRun");
}
else PreventAutoRun = "None";


EnabledNTPServerKEY = wmi_reg_enum_value(wmi_handle:handle, key:"Software\Policies\Microsoft\W32Time\TimeProviders\NtpServer");
EnabledNTPServerKEY = tolower(EnabledNTPServerKEY);
if ("enabled" >< EnabledNTPServerKEY)
{
  EnabledNTPServer = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Policies\Microsoft\W32Time\TimeProviders\NtpServer", val_name:"Enabled");
}
else EnabledNTPServer = "None";

HeadlinesKEY = wmi_reg_enum_value(wmi_handle:handle, key:"Software\Policies\Microsoft\PCHealth\HelpSvc");
HeadlinesKEY = tolower(HeadlinesKEY);
if ("headlines" >< HeadlinesKEY)
{
  Headlines = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Policies\Microsoft\PCHealth\HelpSvc", val_name:"Headlines");
}
else Headlines = "None";

DisableWindowsUpdateAccessKEY = wmi_reg_enum_value(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\WindowsUpdate");
DisableWindowsUpdateAccessKEY = tolower(DisableWindowsUpdateAccessKEY);
if ("disablewindowsupdateaccess" >< DisableWindowsUpdateAccessKEY)
{
  DisableWindowsUpdateAccess  = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\WindowsUpdate", val_name:"DisableWindowsUpdateAccess");
}
else DisableWindowsUpdateAccess = "None";

DontSearchWindowsUpdateKEY = wmi_reg_enum_value(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\DriverSearching");
DontSearchWindowsUpdateKEY = tolower(DontSearchWindowsUpdateKEY);
if ("dontsearchwindowsupdate" >< DontSearchWindowsUpdateKEY)
{
  DontSearchWindowsUpdate = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\DriverSearching", val_name:"DontSearchWindowsUpdate");
}
else DontSearchWindowsUpdate = "None";

NoRegistrationKEY = wmi_reg_enum_value(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\Registration Wizard Control");
NoRegistrationKEY = tolower(NoRegistrationKEY);
if ("noregistration" >< NoRegistrationKEY)
{
  NoRegistration = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\Registration Wizard Control", val_name:"NoRegistration");
}
else NoRegistration = "None";

DisableRootAutoUpdateKEY = wmi_reg_enum_value(wmi_handle:handle, key:"Software\Policies\Microsoft\SystemCertificates\AuthRoot");
DisableRootAutoUpdateKEY = tolower(DisableRootAutoUpdateKEY);
if ("disablerootautoupdate" >< DisableRootAutoUpdateKEY)
{
  DisableRootAutoUpdate = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Policies\Microsoft\SystemCertificates\AuthRoot", val_name:"DisableRootAutoUpdate");
}
else DisableRootAutoUpdate = "None";

MicrosoftEventVwrDisableLinksKEY = wmi_reg_enum_value(wmi_handle:handle, key:"Software\Policies\Microsoft\EventViewer");
MicrosoftEventVwrDisableLinksKEY = tolower(MicrosoftEventVwrDisableLinksKEY);
if ("microsofteventvwrdisablelinks" >< MicrosoftEventVwrDisableLinksKEY)
{
  MicrosoftEventVwrDisableLinks = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Policies\Microsoft\EventViewer", val_name:"MicrosoftEventVwrDisableLinks");
}
else MicrosoftEventVwrDisableLinks = "None";

NoInternetOpenWithKEY = wmi_reg_enum_value(wmi_handle:handle, key:"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer");
NoInternetOpenWithKEY = tolower(NoInternetOpenWithKEY);
if ("nointernetopenwith" >< NoInternetOpenWithKEY)
{
  NoInternetOpenWith = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", val_name:"NoInternetOpenWith");
}
else NoInternetOpenWith = "None";

DoReportKEY = wmi_reg_enum_value(wmi_handle:handle, key:"Software\Policies\Microsoft\PCHealth\ErrorReporting");
DoReportKEY = tolower(DoReportKEY);
if ("doreport" >< DoReportKEY)
{
  DoReport = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Policies\Microsoft\PCHealth\ErrorReporting", val_name:"DoReport");
}
else DoReport = "None";



set_kb_item(name:"WMI/XP-InetComm/NoUpdateCheck", value:NoUpdateCheck);
set_kb_item(name:"WMI/XP-InetComm/PreventAutoRun", value:PreventAutoRun);
set_kb_item(name:"WMI/XP-InetComm/EnabledNTPServer", value:EnabledNTPServer);
set_kb_item(name:"WMI/XP-InetComm/Headlines", value:Headlines);
set_kb_item(name:"WMI/XP-InetComm/DisableWindowsUpdateAccess", value:DisableWindowsUpdateAccess);
set_kb_item(name:"WMI/XP-InetComm/DontSearchWindowsUpdate", value:DontSearchWindowsUpdate);
set_kb_item(name:"WMI/XP-InetComm/NoRegistration", value:NoRegistration);
set_kb_item(name:"WMI/XP-InetComm/DisableRootAutoUpdate", value:DisableRootAutoUpdate);
set_kb_item(name:"WMI/XP-InetComm/MicrosoftEventVwrDisableLinks", value:MicrosoftEventVwrDisableLinks);
set_kb_item(name:"WMI/XP-InetComm/NoInternetOpenWith", value:NoInternetOpenWith);
set_kb_item(name:"WMI/XP-InetComm/DoReport", value:DoReport);

wmi_close(wmi_handle:handle);

exit(0);
