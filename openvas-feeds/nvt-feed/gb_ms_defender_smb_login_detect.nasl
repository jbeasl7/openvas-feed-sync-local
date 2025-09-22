# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.129014");
  script_version("2025-08-07T05:44:51+0000");
  script_tag(name:"last_modification", value:"2025-08-07 05:44:51 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-13 10:00:00 +0200 (Tue, 13 May 2025)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Microsoft/Windows Defender Detection (Windows SMB Login)");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_category(ACT_GATHER_INFO);

  script_dependencies("smb_reg_service_pack.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_gather_service_list_win.nasl");

  script_mandatory_keys("SMB/WindowsName", "SMB/WindowsBuild");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects and gathers information of Microsoft/Windows Defender
  on Windows operating systems. Supports Windows 7 and Server 2008 onwards. The information is
  retrieved via Powershell.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("smb_nt.inc");
include("powershell_func.inc");
include("cpe.inc");
include("version_func.inc");

if(get_kb_item("win/lsc/disable_win_cmd_exec"))
  exit(0);

windows_version = get_kb_item("SMB/WindowsName");
windows_build = get_kb_item("SMB/WindowsBuild");

# nb: Get service information
if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM"){
  if(get_kb_item("SMB/gather_service_list_win/error"))
    exit(0);

  if(!service_list = get_kb_item("SMB/gather_service_list_win/services"))
    exit(0);
}else{
  # depending on the windows version we have to use a different command
  if( windows_version =~ "Windows 7" || windows_version =~ "Windows Server \(R\) 2008" || windows_version =~ "Windows Server 2008 R2" ){
    cmd = "$services = Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue | Where-Object {$_.Name -eq 'windefend'} | foreach-object {$_.DisplayName + ';' + $_.Name + ';' + $_.State + ';' + $_.ServiceType + ';' + $_.StartMode + ';' + $_.PathName + ';' };$count = ($services -split [Environment]::NewLine).Count | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum;$max = $services -split [Environment]::NewLine | foreach-object {$_.length} | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum;$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size (($max + 5), ($count + 5));$services;";
  } else {
    cmd = "Get-CimInstance -Class Win32_Service -ErrorAction SilentlyContinue | Where-Object {$_.Name -eq 'windefend'} | foreach-object {$_.DisplayName + ';' + $_.Name + ';' + $_.State + ';' + $_.ServiceType + ';' + $_.StartMode + ';' + $_.PathName + ';' }";
  }
  service_list = powershell_cmd(cmd:cmd);
  if(!service_list)
    exit(0);
}

# Output: DisplayName;Name;Status;ServiceType;StartMode;PathToExecutable;
# Example: Microsoft Defender Antivirus Service;WinDefend;Running;WinDefend;Win32OwnProcess;Automatic;"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25030.2-0\MsMpEng.exe";
service_info_defender = egrep(string:service_list, pattern:"(.*);(WinDefend);(.*);(.*);(.*);(.*);");

# exit if service doesn't exist
if(!service_info_defender)
  exit(0);

# split defender service information
if(service_info_defender){
  value = eregmatch( string:service_info_defender, pattern:"(.*);(WinDefend);(.*);(.*);(.*);(.*);" );
  defender_display_name = value[1];
  defender_service_name = value[2];
  defender_service_status = value[3];
  defender_start_type = value[5];
  defender_install_path = value[6];
}

# exit if service is disabled
if(defender_start_type =~ "Disabled")
  exit(0);

if( windows_version =~ "Windows 7" || windows_version =~ "Windows Server \(R\) 2008" || windows_version =~ "Windows Server 2008 R2" || windows_version =~ "Windows 8" ){
  # For windows 7, server 2008/2008R2 and windows 8/8.1
  # Gathers engine version, mpclient.dll version, mpcmdrun.exe version and mpcmdrun.exe location
  win_cmd = "$engine_version = Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Defender\Signature Updates' -ErrorAction SilentlyContinue | ForEach-Object { $_.EngineVersion };$progfiledir = Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion' -ErrorAction SilentlyContinue | ForEach-Object { $_.ProgramFilesDir };$defender_location = Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Defender' -ErrorAction SilentlyContinue | ForEach-Object { $_.InstallLocation };if(!$defender_location){$defender_location = '{0}\Windows Defender\' -f $progfiledir};$mpclient_version = Get-Item -Path ('{0}Mpclient.dll' -f $defender_location) -ErrorAction SilentlyContinue | ForEach-Object {$_.VersionInfo.FileVersion};$mpcmdrun_version = Get-Item -Path ('{0}mpcmdrun.exe' -f $defender_location) -ErrorAction SilentlyContinue | ForEach-Object {$_.VersionInfo.FileVersion};'{0};{1};{2};{3};' -f $engine_version,$mpclient_version,$mpcmdrun_version,$defender_location;";
  win_output = powershell_cmd(cmd:win_cmd);
  if( !win_output )
    exit(0);

  # Example: 1.1.12400.0;6.1.7601.18170 (win7sp1_gdr.130526-1536);6.1.7600.16385 (win7_rtm.090713-1255);C:\Program Files\Windows Defender\;
  win_pattern = "(.*){0,1};(([0-9.]{7,}) {0,1}(\(.*\)){0,1}){0,1};(([0-9.]{7,}) {0,1}(\(.*\)){0,1}){0,1};(.*);";
  win_values = eregmatch( string:win_output, pattern:win_pattern );

  engine_version = win_values[1]; # malware protection engine version
  mpclient_version = win_values[3]; # this is the defender version for some older advisories / defender updates
  mpcmdrun_version = win_values[6]; # this is the defender version and also called platform version in most advisories
  defender_location = win_values[8]; # windows defender location

  if( mpclient_version && mpcmdrun_version ){
    if( version_is_less( version:mpcmdrun_version, test_version:mpclient_version ) ){
      defender_version = mpclient_version;
    }else{
      defender_version = mpcmdrun_version;
    }
  } else if( mpclient_version && !mpcmdrun_version ){
    defender_version = mpclient_version;
  } else if( !mpclient_version && mpcmdrun_version ){
    defender_version = mpcmdrun_version;
  }

  if( !engine_version && !defender_version )
    exit(0);

}else if( windows_version =~ "Windows Server 2012" || windows_build >= "10240"){
  # For windows 10/11 and server 2016/2019/2022/2025
  # Gathers engine version, mpcmdrun.exe version and mpcmdrun.exe location
  addv_cmd = "$engine_version = Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Defender\Signature Updates' -ErrorAction SilentlyContinue | ForEach-Object { $_.EngineVersion };$progfiledir = Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion' -ErrorAction SilentlyContinue | ForEach-Object { $_.ProgramFilesDir };$defender_location = Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Defender' -ErrorAction SilentlyContinue | ForEach-Object { $_.InstallLocation };if(!$defender_location){$defender_location = '{0}\Windows Defender\' -f $progfiledir};$mpcmdrun_version = Get-Item -Path ('{0}mpcmdrun.exe' -f $defender_location) -ErrorAction SilentlyContinue | ForEach-Object {$_.VersionInfo.FileVersion};'{0};{1};{2};' -f $engine_version,$mpcmdrun_version,$defender_location;";
  addv_output = powershell_cmd(cmd:addv_cmd);
  if( !addv_output )
    exit(0);

  # Example: 1.1.25040.1;4.18.25030.2 (000028f0c1f345a538ea89b768605447f1c02bdf);C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25030.2-0\;
  addv_pattern = "(.*){0,1};(([0-9.]{7,}) {0,1}(\(.*\)){0,1}){0,1};(.*);";
  additional_values = eregmatch( string:addv_output, pattern:addv_pattern );

  engine_version = additional_values[1]; # malware protection engine version
  defender_version = additional_values[3]; # this is the mpcmdrun.exe version, also called defender version or platform version in most advisories
  defender_location = additional_values[5]; # windows defender location

  if( !engine_version && !defender_version )
    exit(0);

}else{
  # unsupported windows version
  exit(0);
}

if( service_info_defender && defender_start_type !~ "Disabled"){

  set_kb_item( name:"microsoft/defender/detected", value:TRUE );
  set_kb_item( name:"microsoft/defender/win/detected", value:TRUE );
  set_kb_item( name:"microsoft/defender/service_start_type", value:defender_start_type );
  set_kb_item( name:"microsoft/defender/service_status", value:defender_service_status );

  # needed for older defender advisories
  if( mpclient_version ){
    set_kb_item( name:"microsoft/defender/mpclient", value:mpclient_version );
  }

  # malware protection engine
  if( engine_version ){
    set_kb_item( name:"microsoft/defender/mpe_version", value:engine_version );
    concluded += '\nEngineVersion:   ' + engine_version;

    if( !defender_location )
      defender_location = "unknown";

    register_and_report_cpe( app:"Microsoft Malware Protection Engine", ver:engine_version, concluded:concluded,
                            base:"cpe:/a:microsoft:malware_protection_platform:", expr:"^([0-9.]+)", insloc:defender_location,
                            regService:"smb-login", regPort:0 );
  }

  # microsoft defender platform version
  if( defender_version ){
    set_kb_item( name:"microsoft/defender/platform_version", value:defender_version );
    concluded += '\nPlatformVersion: ' + defender_version;

    register_and_report_cpe( app:"Microsoft Defender Antivirus", ver:defender_version, concluded:concluded,
                            base:"cpe:/a:microsoft:windows_defender:", expr:"^([0-9.]+)", insloc:defender_location,
                            regService:"smb-login", regPort:0 );
  }
}

exit(0);
