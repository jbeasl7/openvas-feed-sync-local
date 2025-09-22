# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96052");
  script_version("2025-03-07T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-03-07 05:38:18 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Test if passfilt.dll is installed - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Test over WMI if passfilt.dll is installed and the necessary
  registry entry set.");

  exit(0);
}

include("wmi_os.inc");
include("smb_nt.inc");
include("powershell_func.inc");

host    = get_host_ip();
usrname = kb_smb_login();
domain  = kb_smb_domain();
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd = kb_smb_password();

OSVER = get_kb_item("WMI/WMI_OSVER");

if(!OSVER || (OSVER >< "none")){
    set_kb_item(name:"WMI/Passfilt.dll", value:"error");
    set_kb_item(name:"WMI/Passfilt.reg", value:"error");
    set_kb_item(name:"WMI/Passfilt/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
    exit(0);
}

handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handlereg){
  set_kb_item(name:"WMI/Passfilt.dll", value:"error");
  set_kb_item(name:"WMI/Passfilt.reg", value:"error");
  set_kb_item(name:"WMI/Passfilt/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handlereg);
  exit(0);
}

PASSFILT = wmi_reg_get_mul_string_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Control\Lsa", val_name:"Notification Packages");
windirpath = wmi_os_windir();

if (OSVER < 6){
  val01 = split(windirpath, sep:"|", keep:0);
  val02 = split(val01[4], sep:"\", keep:0);
  val03 = eregmatch(pattern:".*[A-Za-z0-9-_/./(/)!$%&=+#@~^]", string:val02[1]);
  pathdll = val02[0] + "\\" + val03[0] + "\\system32\\passfilt.dll";
}
if (OSVER >= 6){
  val01 = split(windirpath, sep:'\n', keep:0);
  val02 = split(val01[1], sep:"\", keep:0);
  val03 = eregmatch(pattern:".*[A-Za-z0-9-_/./(/)!$%&=+#@~^]", string:val02[1]);
  pathdll = val02[0] + "\\" + val03[0] + "\\system32\\passfilt.dll";
}

fileExistdll = powershell_wmi_file_check_file_exists(filePath:pathdll);

if(fileExistdll == "1"){
   note = note + val02[0] + '\\' + val03[0] + '\\system32\\passfilt.dll';
}
else {
  note = "FALSE";
}

if (!note) note = "None";
if (!PASSFILT) PASSFILT = "None";

set_kb_item(name:"WMI/Passfilt.dll", value:note);
set_kb_item(name:"WMI/Passfilt.reg", value:PASSFILT);


wmi_close(wmi_handle:handlereg);

exit(0);
