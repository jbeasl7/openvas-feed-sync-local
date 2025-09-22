# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96001");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("CD-ROM Autostart - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"The script detects if CD-ROM Autostart is activated.");

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
  set_kb_item(name:"WMI/CD_Autostart", value:"error");
  set_kb_item(name:"WMI/CD_Autostart/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

handle = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/CD_Autostart", value:"error");
  set_kb_item(name:"WMI/CD_Autostart/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  exit(0);
}

CDAUTOKEY = wmi_reg_enum_value(wmi_handle:handle, key:"SYSTEM\CurrentControlSet\Services\Cdrom");

if(!CDAUTOKEY){
  log_message(port:0, proto: "IT-Grundschutz", data:"Registry Path not found.");
  set_kb_item(name:"WMI/CD_Autostart", value:"error");
  wmi_close(wmi_handle:handle);
  exit(0);
}else if ("AutoRun" >!< CDAUTOKEY){
  log_message(port:0, proto: "IT-Grundschutz", data:"Registry Value not found.");
  set_kb_item(name:"WMI/CD_Autostart", value:"error");
  wmi_close(wmi_handle:handle);
  exit(0);
}

cdauto = wmi_reg_get_dword_val(wmi_handle:handle, key:"SYSTEM\CurrentControlSet\Services\Cdrom", val_name:"AutoRun");

if(cdauto == 1){
  set_kb_item(name:"WMI/CD_Autostart", value:"on");
  wmi_close(wmi_handle:handle);
exit(0);
}

if(cdauto == "0"){
  set_kb_item(name:"WMI/CD_Autostart", value:"off");
  wmi_close(wmi_handle:handle);
exit(0);
}
