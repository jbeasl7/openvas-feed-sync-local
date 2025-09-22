# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96024");
  script_version("2025-03-07T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-03-07 05:38:18 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("List all Installed ODBC Driver over WMI - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_IIS_OpenPorts.nasl",
                      "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"List all installed ODBC Driver over WMI if IIS installed.");

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

IISVER  = get_kb_item("WMI/IISandPorts");
OSVER = get_kb_item("WMI/WMI_OSVER");

if(!OSVER || OSVER >< "none"){
    set_kb_item(name:"WMI/ODBCINST", value:"error");
    set_kb_item(name:"WMI/ODBCINST/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
    exit(0);
}

handle = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
    set_kb_item(name:"WMI/ODBCINST", value:"error");
    set_kb_item(name:"WMI/ODBCINST/log", value:"wmi_connect: WMI Connect failed.");
    wmi_close(wmi_handle:handle);
exit(0);
}

if(IISVER >< "None"){
    set_kb_item(name:"WMI/ODBCINST", value:"None");
    set_kb_item(name:"WMI/ODBCINST/log", value: "IT-Grundschutz: IIS is not installed");
    wmi_close(wmi_handle:handle);
    exit(0);
}

ODBC = wmi_reg_enum_key(wmi_handle:handle, key:"SOFTWARE\ODBC\ODBCINST.INI");

if (ODBC){
ODBC = split(ODBC, sep:"|", keep:0);
for(i=0; i<max_index(ODBC); i++)
  {
    ODBCval = ODBCval + ODBC[i] + '\n';
  }
  ODBC = ODBCval;
}

if(!ODBC) ODBC = "None";
set_kb_item(name:"WMI/ODBCINST", value:ODBC);

wmi_close(wmi_handle:handle);

exit(0);

