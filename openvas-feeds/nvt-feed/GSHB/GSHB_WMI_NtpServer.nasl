# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96015");
  script_version("2025-03-07T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-03-07 05:38:18 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("WMI NTP Server - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"Tests WMI NTP Server.");

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
  set_kb_item(name:"WMI/NtpServer", value:"error");
  set_kb_item(name:"WMI/Service/w32time", value:"error");
  set_kb_item(name:"WMI/NtpServer/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);
handle = wmi_connect(host:host, username:usrname, password:passwd);

if(!handle || !handlereg){
  set_kb_item(name:"WMI/NtpServer", value:"error");
  set_kb_item(name:"WMI/NtpServer/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  wmi_close(wmi_handle:handlereg);
  exit(0);
}


NtpServer = wmi_reg_get_sz(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\W32Time\Parameters", key_name:"NtpServer");

query = 'select state  from Win32_Service WHERE NAME = "w32time"';
w32timeService = wmi_query(wmi_handle:handle, query:query);

if(!NtpServer) NtpServer = "None";
set_kb_item(name:"WMI/NtpServer", value:NtpServer);
set_kb_item(name:"WMI/Service/w32time", value:w32timeService);

wmi_close(wmi_handle:handle);
wmi_close(wmi_handle:handlereg);

exit(0);
