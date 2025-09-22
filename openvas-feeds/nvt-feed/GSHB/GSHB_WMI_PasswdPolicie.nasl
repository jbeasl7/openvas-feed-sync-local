# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96033");
  script_version("2025-03-21T15:40:43+0000");
  script_tag(name:"last_modification", value:"2025-03-21 15:40:43 +0000 (Fri, 21 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Read the Windows Password Policy over SMB - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("IT-Grundschutz");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"This script reads the Windows Password Policy configuration
  over SMB.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("powershell_func.inc");

OSVER = get_kb_item("WMI/WMI_OSVER");
WindowsDomainrole = get_kb_item("WMI/WMI_WindowsDomainrole");

if(!OSVER || OSVER >< "none"){
  set_kb_item(name:"WMI/lockoutpolicy", value:"error");
  set_kb_item(name:"WMI/passwdpolicy", value:"error");
  set_kb_item(name:"WMI/passwdpolicy/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

ps_cmd = "Get-Ciminstance -Namespace 'root\RSOP\Computer' -query 'Select * from RSOP_SecuritySettingNumeric where precedence=1' | Select-Object KeyName, Setting | foreach-object { $_.KeyName + ';' + $_.Setting + ';' }";
pwdList = powershell_cmd(cmd:ps_cmd);

if(pwdList){
  foreach entry (split(pwdList)){
    value = eregmatch(string:entry, pattern:"(.*);(.*);");
    set_kb_item(name:"WMI/passwdpolicy/" + value[1], value:value[2]);
  }
}else{
  set_kb_item(name:"WMI/passwdpolicy", value:"False");
}

ps_cmd = "Get-Ciminstance -Namespace 'root\RSOP\Computer' -query 'Select * from RSOP_SecuritySettingBoolean where precedence=1' | Select-Object KeyName, Setting | foreach-object { $_.KeyName + ';' + $_.Setting + ';' }";
lkList = powershell_cmd(cmd:ps_cmd);

if(lkList){
  foreach entry (split(lkList)){
    value = eregmatch(string:entry, pattern:"(.*);(.*);");
    set_kb_item(name:"WMI/lockoutpolicy/" + value[1], value:value[2]);
  }
}else{
  set_kb_item(name:"WMI/lockoutpolicy", value:"False");
}

if( OSVER >= "6.2" ){
  pinLogin = registry_get_dword( key:"SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowSignInOptions", item:"value", type:"HKLM");
  if( pinLogin || pinLogin == "0" ){
    set_kb_item(name:"WMI/passwdpolicy/pinLogin", value:pinLogin);
  }else{
    set_kb_item(name:"WMI/passwdpolicy/pinLogin", value:"None");
  }
}

set_kb_item(name:"WMI/lockoutpolicy/stat", value:"ok");
set_kb_item(name:"WMI/passwdpolicy/stat", value:"ok");

exit(0);
