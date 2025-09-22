# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96999");
  script_version("2025-03-07T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-03-07 05:38:18 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Get OS Version, OS Type, OS Servicepack and OS Name over WMI - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("IT-Grundschutz");
  script_dependencies("smb_nativelanman.nasl", "netbios_name_get.nasl", "lsc_options.nasl");
  script_exclude_keys("win/lsc/disable_win_cmd_exec");
  script_require_ports(139, 445);
  # nb: Don't add a script_mandatory_keys to e.g. WMI/access_successful or any other tag like
  # script_exclude_keys as other VTs having a dependency on this VT require to have the
  # "errorval" below set to "none".

  script_tag(name:"summary", value:"Get OS Version, OS Type, OS Servicepack and OS Name over WMI.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("wmi_os.inc");
include("smb_nt.inc");
include("powershell_func.inc");

if(is_win_cmd_exec_disabled())
  exit(0);

host    = get_host_ip();
usrname = kb_smb_login();
passwd = kb_smb_password();
samba  = kb_smb_is_samba();

# nb: Don't change this without changing the same text of the VTs having
# a dependency to this VT.
errorval = "none";
if(samba){
  set_kb_item(name:"WMI/WMI_WindowsDomain", value:errorval);
  set_kb_item(name:"WMI/WMI_WindowsDomainrole", value:errorval);
  set_kb_item(name:"WMI/WMI_OSVER", value:errorval);
  set_kb_item(name:"WMI/WMI_OSSP", value:errorval);
  set_kb_item(name:"WMI/WMI_OSTYPE", value:errorval);
  set_kb_item(name:"WMI/WMI_OSDRIVE", value:errorval);
  set_kb_item(name:"WMI/WMI_OSWINDIR", value:errorval);
  set_kb_item(name:"WMI/WMI_OSNAME", value:errorval);
  set_kb_item(name:"WMI/WMI_OS/log", value:"On the Target System runs Samba, it is not an Microsoft System.");
  exit(0);
}

if(!host || !usrname || !passwd){
  set_kb_item(name:"WMI/WMI_WindowsDomain", value:errorval);
  set_kb_item(name:"WMI/WMI_WindowsDomainrole", value:errorval);
  set_kb_item(name:"WMI/WMI_OSVER", value:errorval);
  set_kb_item(name:"WMI/WMI_OSSP", value:errorval);
  set_kb_item(name:"WMI/WMI_OSTYPE", value:errorval);
  set_kb_item(name:"WMI/WMI_OSDRIVE", value:errorval);
  set_kb_item(name:"WMI/WMI_OSWINDIR", value:errorval);
  set_kb_item(name:"WMI/WMI_OSNAME", value:errorval);
  set_kb_item(name:"WMI/WMI_OS/log", value:"No Host, Username or Password.");
  exit(0);
}

OSVER = wmi_os_version();
OSSP =  wmi_os_sp();
if(OSSP != 1){
  OSSP = eregmatch(pattern:"[0-9]", string:OSSP);
  OSSP = OSSP[0];
} else {
  OSSP = "Without SP";
}

OSTYPE = wmi_os_type();

OSArchitecture = powershell_wmi_query(classname:"Win32_OperatingSystem", properties:"OSArchitecture");

OSNAME = powershell_wmi_query(classname:"Win32_OperatingSystem", properties:"Caption");
if(OSVER <= 6){
  OSNAME = split(OSNAME[1], sep:'|', keep:FALSE);
  OSNAME = OSNAME[0];
} else {
  OSNAME = OSNAME[1];
}

Domain = powershell_wmi_query(classname:"Win32_ComputerSystem", properties:"Domain");
windirpath = wmi_os_windir();

if(OSVER < 6){
  val01 = split(windirpath, sep:"|", keep:FALSE);
  val02 = split(val01[4], sep:"\", keep:FALSE);
  OSDRIVE = val02[0];
} else {
  val01 = split(windirpath, sep:":", keep:FALSE);
  val04 = eregmatch(pattern:"[A-Z]$", string:val01[0]);
  OSDRIVE = val04[0] + ":";
}

OSWINDIR = wmi_os_windir();
if(OSVER < '6.0'){
  OSWINDIR = split(OSWINDIR, sep:"|", keep:FALSE);
  OSWINDIR = ereg_replace(pattern:'\n', string:OSWINDIR[4], replace:'');
} else {
  OSWINDIR = split(OSWINDIR, sep:'\n', keep:FALSE);
  OSWINDIR = OSWINDIR[1];
}

Domainrole = powershell_wmi_query(classname:"Win32_ComputerSystem", properties:"DomainRole");
if(!Domainrole)
  Domainrole = "none";
#Domainrole Definition:
#0 (0x0) Standalone Workstation
#1 (0x1) Member Workstation
#2 (0x2) Standalone Server
#3 (0x3) Member Server
#4 (0x4) Backup Domain Controller
#5 (0x5) Primary Domain Controller

if(!OSVER) OSVER = errorval;
if(!OSSP) OSSP = errorval;
if(!OSTYPE) OSTYPE = errorval;
if(!OSArchitecture[1]) OSArchitecture[1] = errorval;
if(!OSNAME) OSNAME = errorval;
if(!OSDRIVE) OSDRIVE = errorval;
if(!OSWINDIR) OSWINDIR = errorval;
if(!Domain) Domain = errorval;

set_kb_item(name:"WMI/WMI_WindowsDomain", value:Domain);
set_kb_item(name:"WMI/WMI_WindowsDomainrole", value:Domainrole);
set_kb_item(name:"WMI/WMI_OSVER", value:OSVER);
set_kb_item(name:"WMI/WMI_OSSP", value:OSSP);
set_kb_item(name:"WMI/WMI_OSTYPE", value:OSTYPE);
set_kb_item(name:"WMI/WMI_OSArchitecture", value:OSArchitecture[1]);
set_kb_item(name:"WMI/WMI_OSDRIVE", value:OSDRIVE);
set_kb_item(name:"WMI/WMI_OSWINDIR", value:OSWINDIR);
set_kb_item(name:"WMI/WMI_OSNAME", value:OSNAME);
set_kb_item(name:"WMI/WMI_OS/log", value:"ok");

exit(0);
