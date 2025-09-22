# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.129015");
  script_version("2025-08-07T05:44:51+0000");
  script_tag(name:"last_modification", value:"2025-08-07 05:44:51 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-13 10:00:00 +0200 (Tue, 13 May 2025)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Microsoft Security Essentials Detection (Windows SMB Login)");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_category(ACT_GATHER_INFO);

  script_dependencies("smb_reg_service_pack.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_gather_service_list_win.nasl");

  script_mandatory_keys("SMB/WindowsName", "SMB/WindowsBuild");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects and gathers information of Microsoft Security
  Essentials. Supports following operating systems:

  - Windows XP SP3

  - Vista SP1

  - Windows 7

  The information is retrieved via Powershell.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("smb_nt.inc");
include("powershell_func.inc");
include("cpe.inc");
include("secpod_reg.inc");

windows_version = get_kb_item("SMB/WindowsName");
if( windows_version !~ "Windows 7" && hotfix_check_sp( xp:4, winVista:2 ) <= 0 )
  exit(0);

if( get_kb_item("win/lsc/disable_win_cmd_exec" ))
  exit(0);

# nb: Check if powershell version is at least 2 and if the product is found in registry
cmd = "if(($PSVersionTable | ForEach-Object {$_.PSVersion.Major}) -lt 2 ){'unsupported';}else{(get-childitem 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\' | foreach-object { $_.pspath} ) | where {$_ -ne $NULL} | foreach-object { Get-ItemProperty $_} | where {$_.DisplayName -eq 'Microsoft Security Essentials'} | foreach-object {$_.DisplayName}}";
software_found = powershell_cmd(cmd:cmd);

# Exit if software is not found or powershell version is not supported
if( !software_found || software_found =~ "unsupported" )
  exit(0);

# nb: Get service information
if(( FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM" ) && windows_version =~ "Windows 7" ){
  if( get_kb_item("SMB/gather_service_list_win/error" ))
    exit(0);

  if( !service_list = get_kb_item("SMB/gather_service_list_win/services" ))
    exit(0);
}else{
  ps_cmd = "$services = Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue | Where-Object {$_.Name -eq 'msmpsvc'} | foreach-object {$_.DisplayName + ';' + $_.Name + ';' + $_.State + ';' + $_.ServiceType + ';' + $_.StartMode + ';' + $_.PathName + ';' };$count = ($services -split [Environment]::NewLine).Count | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum;$max = $services -split [Environment]::NewLine | foreach-object {$_.length} | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum;$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size (($max + 5), ($count + 5));$services;";

  service_list = powershell_cmd(cmd:ps_cmd);
  if( !service_list )
    exit(0);
}

# Output: DisplayName;Name;Status;ServiceType;StartMode;PathToExecutable;
# Example: Microsoft Antimalware Service;msmpsvc;Running;msmpsvc;Win32OwnProcess;;"c:\Program Files\Microsoft Security Client\MsMpEng.exe";
service_info_antimalware = egrep( string:service_list, pattern:"(.*);(MsMpSvc);(.*);(.*);(.*);(.*);" );

# exit if service doesn't exist
if( !service_info_antimalware )
  exit(0);

# split antimalware service information
if( service_info_antimalware ){
  value = eregmatch( string:service_info_antimalware, pattern:"(.*);(MsMpSvc);(.*);(.*);(.*);(.*);" );
  antimalware_display_name = value[1];
  antimalware_service_name = value[2];
  antimalware_service_status = value[3];
  antimalware_start_type = value[5];
  antimalware_install_path = value[6];
}

# exit if service is disabled
if( antimalware_start_type =~ "Disabled" )
  exit(0);

# Gathers engine version, mpcmdrun.exe version, and location of mpcmdrun.exe
win_cmd = "$amw_engine_version = Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Microsoft Antimalware\Signature Updates' -ErrorAction SilentlyContinue | ForEach-Object { $_.EngineVersion };$progfiledir = Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion' -ErrorAction SilentlyContinue | ForEach-Object { $_.ProgramFilesDir };$se_install_location = Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Microsoft Antimalware' -ErrorAction SilentlyContinue | ForEach-Object { $_.InstallLocation };$se_mpcmdrun_version = Get-Item -Path ('{0}\mpcmdrun.exe' -f $se_install_location) -ErrorAction SilentlyContinue | ForEach-Object {$_.VersionInfo.FileVersion};'{0};{1};{2};' -f $amw_engine_version,$se_mpcmdrun_version,$se_install_location;";
win_output = powershell_cmd(cmd:win_cmd);
if( !win_output )
  exit(0);

# Example: 1.1.25040.1;6.1.7601.18170 (win7sp1_gdr.130526-1536);c:\Program Files\Microsoft Security Client\;
win_pattern = "(.*){0,1};(([0-9.]{7,}) {0,1}(\(.*\)){0,1}){0,1};(.*);";
win_values = eregmatch( string:win_output, pattern:win_pattern );

amw_engine_version = win_values[1]; # malware protection engine for antimalware service which is used by microsoft security essentials
se_mpcmdrun_version = win_values[3]; # this is the microsoft security essentials version
se_install_location = win_values[5]; # this is location for mpcmdrun.exe

if( !amw_engine_version && !se_mpcmdrun_version )
  exit(0);

if( software_found && service_info_antimalware && antimalware_start_type !~ "Disabled" ){

  set_kb_item( name:"microsoft/security_essentials/detected", value:TRUE );
  set_kb_item( name:"microsoft/security_essentials/win/detected", value:TRUE );
  set_kb_item( name:"microsoft/security_essentials/service_start_type", value:antimalware_start_type );
  set_kb_item( name:"microsoft/security_essentials/service_status", value:antimalware_service_status );

  if( amw_engine_version ){
    set_kb_item( name:"microsoft/security_essentials/mpe_version", value:amw_engine_version );
    concluded += '\nEngineVersion:   ' + amw_engine_version;

    if( !se_install_location )
      se_install_location = "unknown";

    register_and_report_cpe( app:"Microsoft Antimalware Service", ver:amw_engine_version, concluded:concluded,
                            base:"cpe:/a:microsoft:antimalware_service:", expr:"^([0-9.]+)", insloc:se_install_location,
                            regService:"smb-login", regPort:0 );
  }

  if( se_mpcmdrun_version ){
    set_kb_item( name:"microsoft/security_essentials/platform_version", value:se_mpcmdrun_version );
    concluded += '\nPlatformVersion: ' + se_mpcmdrun_version;

    register_and_report_cpe( app:"Microsoft Security Essentials", ver:se_mpcmdrun_version, concluded:concluded,
                            base:"cpe:/a:microsoft:security_essentials:", expr:"^([0-9.]+)", insloc:se_install_location,
                            regService:"smb-login", regPort:0 );
  }
}

exit(0);
