# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96049");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Checks InternetExplorer Policy for Protected Mode over WMI - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"Checks InternetExplorer Policy for Protected Mode over WMI.");

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

if(!OSVER || OSVER >< "none"){
  set_kb_item(name:"WMI/ProtModeIntraZone", value:"error");
  set_kb_item(name:"WMI/ProtModeTrustZone", value:"error");
  set_kb_item(name:"WMI/ProtModeInterZone", value:"error");
  set_kb_item(name:"WMI/ProtModeRestrZone", value:"error");
  set_kb_item(name:"WMI/ProtMode/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

handle = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/ProtModeIntraZone", value:"error");
  set_kb_item(name:"WMI/ProtModeTrustZone", value:"error");
  set_kb_item(name:"WMI/ProtModeInterZone", value:"error");
  set_kb_item(name:"WMI/ProtModeRestrZone", value:"error");
  set_kb_item(name:"WMI/ProtMode/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  exit(0);
}

IntranetZone = wmi_reg_enum_value(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1");
TrustedSiteZone = wmi_reg_enum_value(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2");
InternetZone = wmi_reg_enum_value(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3");
RestrictedSideZone = wmi_reg_enum_value(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4");

if(OSVER  <  "6.0"){
  set_kb_item(name:"WMI/ProtModeIntraZone", value:"prevista");
  set_kb_item(name:"WMI/ProtModeTrustZone", value:"prevista");
  set_kb_item(name:"WMI/ProtModeInterZone", value:"prevista");
  set_kb_item(name:"WMI/ProtModeRestrZone", value:"prevista");
  wmi_close(wmi_handle:handle);
  exit(0);
}

if ("2500" >< IntranetZone){
  ProtModeIntraZone = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1", val_name:"2500");
}else ProtModeIntraZone = "-1";

if ("2500" >< TrustedSiteZone){
  ProtModeTrustZone = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2", val_name:"2500");
}else ProtModeTrustZone = "-1";

if ("2500" >< InternetZone){
  ProtModeInterZone = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", val_name:"2500");
}else ProtModeInterZone = "-1";

if ("2500" >< RestrictedSideZone){
  ProtModeRestrZone = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", val_name:"2500");
}else ProtModeRestrZone = "-1";

set_kb_item(name:"WMI/ProtModeIntraZone", value:ProtModeIntraZone);
set_kb_item(name:"WMI/ProtModeTrustZone", value:ProtModeTrustZone);
set_kb_item(name:"WMI/ProtModeInterZone", value:ProtModeInterZone);
set_kb_item(name:"WMI/ProtModeRestrZone", value:ProtModeRestrZone);

wmi_close(wmi_handle:handle);
exit(0);

