# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96041");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("File and Folder ACL (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Tools/Present/wmi", "Compliance/Launch/GSHB");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"The script lists File and Folder ACLs.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");

host    = get_host_ip();
usrname = kb_smb_name();
domain  = kb_smb_domain();
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd = kb_smb_password();

OSVER = get_kb_item("WMI/WMI_OSVER");
osdrive = get_kb_item("WMI/WMI_OSDRIVE");
oswindir = get_kb_item("WMI/WMI_OSWINDIR");
pattern = osdrive + '\\\\';
winname = ereg_replace(pattern:pattern, string:oswindir, replace:'');
rootname = winname + '\\..';
autoexec = "autoexec.bat";
share = ereg_replace(pattern:':', string:osdrive, replace:'$');

if(!OSVER || OSVER >< "none"){
  set_kb_item(name:"GSHB/WINSDDL", value:"error");
  set_kb_item(name:"GSHB/ROOTSDDL", value:"error");
  set_kb_item(name:"GSHB/AUTOEXECSDDL", value:"error");
  set_kb_item(name:"GSHB/WINSDDL/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

smbhandle =  smb_connect(host:host, share:share, username:usrname, password:passwd);
#smbhandle =  smb_connect(share:share, username:usrname, password:passwd);

if(!smbhandle){
  set_kb_item(name:"GSHB/WINSDDL", value:"error");
  set_kb_item(name:"GSHB/ROOTSDDL", value:"error");
  set_kb_item(name:"GSHB/AUTOEXECSDDL", value:"error");
  set_kb_item(name:"GSHB/WINSDDL/log", value:"smb_connect: SMB Connect failed.");
  smb_close(smb_handle:smbhandle);
  exit(0);
}

osdrive = get_kb_item("WMI/WMI_OSDRIVE");
oswindir = get_kb_item("WMI/WMI_OSWINDIR");
pattern = osdrive + '\\\\';
winname = ereg_replace(pattern:pattern, string:oswindir, replace:'');
rootname = winname + '\\..';
autoexec = "autoexec.bat";

winsddl = smb_file_SDDL(smb_handle:smbhandle, filename:winname);
rootsddl = smb_file_SDDL(smb_handle:smbhandle, filename:rootname);
autoexecsddl = smb_file_SDDL(smb_handle:smbhandle, filename:autoexec);

if (!winsddl) winsddl = "None";
if (!rootsddl) rootsddl = "None";
if (!autoexecsddl) autoexecsddl = "None";

set_kb_item(name:"GSHB/AUTOEXECSDDL", value:autoexecsddl);
set_kb_item(name:"GSHB/WINSDDL", value:winsddl);
set_kb_item(name:"GSHB/ROOTSDDL", value:rootsddl);

smb_close(smb_handle:smbhandle);

set_kb_item(name:"GSHB/WINSDDL/stat", value:"ok");

exit(0);
