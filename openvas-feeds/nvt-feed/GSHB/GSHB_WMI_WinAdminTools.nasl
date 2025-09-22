# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96016");
  script_version("2025-03-07T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-03-07 05:38:18 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Find Windows Admin Tools over WMI if IIS installed - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_IIS_OpenPorts.nasl",
                      "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"If IIS installed, find Windows Admin Tools over WMI:

  arp.exe, at.exe, atsvc.exe, cacls.exe, cmd.exe, cscript.exe, debug.exe, edit.com, edlin.exe,
  ftp.exe, finger.exe, ipconfig.exe, net.exe, netsh.exe, netstat.exe, nslookup.exe, ping.exe,
  poledit.exe, posix.exe, qbasic.exe, rcp.exe, rdisk.exe, regedit.exe, regedt32.exe, regini.exe,
  regsrv3.exe, rexec.exe, route.exe, rsh.exe, runonce.exe, secfixup.exe, syskey.exe, telnet.exe,
  tftp.exe, tracert.exe, tskill.exe, wscript.exe, xcopy.exe");

  exit(0);
}

include("wmi_os.inc");
include("smb_nt.inc");
include("powershell_func.inc");

IISVER  = get_kb_item("WMI/IISandPorts");
OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");

if(!OSVER || (OSVER >< "none")){
    set_kb_item(name:"WMI/AdminTools", value:"error");
    set_kb_item(name:"WMI/AdminTools/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
    exit(0);
}

windirpath = wmi_os_windir();
sysdirpath = wmi_os_sysdir();

if((IISVER >< "None")){
    set_kb_item(name:"WMI/AdminTools", value:"inapplicable");
    set_kb_item(name:"WMI/AdminTools/log", value:"IT-Grundschutz: No IIS installed, Test not needed!");
    exit(0);
}

program = make_list("arp.exe", "at.exe", "atsvc.exe", "cacls.exe", "cmd.exe",
 "cscript.exe", "debug.exe", "edit.com", "edlin.exe", "ftp.exe", "finger.exe",
 "ipconfig.exe", "net.exe", "netsh.exe", "netstat.exe", "nslookup.exe",
 "ping.exe", "poledit.exe", "posix.exe", "qbasic.exe", "rcp.exe", "rdisk.exe",
 "regedit.exe", "regedt32.exe", "regini.exe", "regsrv3.exe", "rexec.exe",
 "route.exe", "rsh.exe", "runonce.exe", "secfixup.exe", "syskey.exe",
 "telnet.exe", "tftp.exe", "tracert.exe", "tskill.exe", "wscript.exe",
 "xcopy.exe");

if (OSVER < 6){
val01 = split(windirpath, sep:"|", keep:0);
val02 = split(val01[4], sep:"\", keep:0);
val03 = eregmatch(pattern:".*[A-Za-z0-9-_/./(/)!$%&=+#@~^]", string:val02[1]);
path = val02[0] + "\\" + val03[0] + "\\";
}
else {
val01 = split(windirpath, sep:":", keep:0);
val03 = eregmatch(pattern:".*[A-Za-z0-9-_/./(/)!$%&=+#@~^]", string:val01[1]);
val04 = eregmatch(pattern:"[A-Z]$", string:val01[0]);
path = val04[0] + ":\" + val03[0] + "\\";
}

if (OSVER < 6){
val11 = split(sysdirpath, sep:"|", keep:0);
val12 = split(val11[4], sep:"\", keep:0);
val13 = eregmatch(pattern:".*[A-Za-z0-9-_/./(/)!$%&=+#@~^]", string:val12[2]);
syspath = val12[0] + "\\" + val12[1] + "\\" + val13[0] + "\\";
}
else {
val11 = split(sysdirpath, sep:":", keep:0);
val13 = eregmatch(pattern:".*[A-Za-z0-9-_///./(/)!$%&=+#@~^]", string:val11[1]);
val13 = split(val13[0], sep:"\", keep:0);
val15 = eregmatch(pattern:"[A-Z]$", string:val11[0]);
syspath = val15[0] + ":\\" + val13[1] + "\\" + val13[2] + "\\";
}


foreach p (program) {
  fileExist = powershell_wmi_file_check_file_exists( filePath:path + p);
  if(fileExist == "1"){
    if (OSVER < 6) note = note + val02[0] + "\" + val03[0] + "\" + p + '\n';
    if (OSVER >= 6)note = note + val04[0] + ":\" + val03[0] + "\" + p + '\n';
  }
  fileExist = powershell_wmi_file_check_file_exists(filePath:syspath + p);
  if(fileExist == "1"){
    if (OSVER < 6) note = note + val12[0] + "\" + val13[0] + "\" + p + '\n';
    if (OSVER >= 6)note = note + val15[0] + ":\" + val13[1] + "\" + val13[2] + "\" + p + '\n';
  }
}

if(note)set_kb_item(name:"WMI/AdminTools", value:note);
else set_kb_item(name:"WMI/AdminTools", value:"None");

exit(0);
