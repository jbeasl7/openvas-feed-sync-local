# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96026");
  script_version("2025-03-07T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-03-07 05:38:18 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Get all Windows Shares over WMI - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"Get all Windows Shares over WMI and check the Networkaccess for
  Anonymous (IPC$ NullSession).");

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
    set_kb_item(name:"WMI/Shares", value:"error");
    set_kb_item(name:"WMI/IPC", value:"error");
    log_message(port:0, proto: "IT-Grundschutz", data:string("No access to SMB host. Firewall is activated or there is not a Windows system."));
    exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);
handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
    security_message("wmi_connect: WMI Connect failed.");
    set_kb_item(name:"WMI/Shares", value:"error");
    set_kb_item(name:"WMI/IPC", value:"error");
    wmi_close(wmi_handle:handle);
    wmi_close(wmi_handle:handlereg);
    exit(0);
}

query = 'select Name from Win32_Share';
SHARES = wmi_query(wmi_handle:handle, query:query);



IPC = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Control\LSA", val_name:"RestrictAnonymous");

AUTOSHARE = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", val_name:"AutoShareServer");



if(!SHARES) SHARES = "None";
if(!IPC) IPC = "None";
if(!AUTOSHARE) AUTOSHARE = "None";

set_kb_item(name:"WMI/Shares", value:SHARES);
set_kb_item(name:"WMI/IPC", value:IPC);
set_kb_item(name:"WMI/AUTOSHARE", value:AUTOSHARE);

wmi_close(wmi_handle:handle);
wmi_close(wmi_handle:handlereg);


exit(0);
