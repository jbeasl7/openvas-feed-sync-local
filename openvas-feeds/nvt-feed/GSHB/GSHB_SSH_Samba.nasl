# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96093");
  script_version("2025-01-22T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-05-25 17:00:55 +0200 (Tue, 25 May 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Read Samba [global] and [netlogon] Configuration");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"This plugin uses SSH to read the Samba [global] and [netlogon]
  configuration.");

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = get_preference("auth_port_ssh");
if(!port)
  port = ssh_get_port(default:22, ignore_unscanned:TRUE);

sock = ssh_login_or_reuse_connection();
if(!sock) {
  error = ssh_get_error();
  if (!error) error = "No SSH Port or Connection!";
  log_message(port:port, data:error);
#  set_kb_item(name: "GSHB/SAMBA/conf", value:"error");
  set_kb_item(name: "GSHB/SAMBA/global", value:"error");
  set_kb_item(name: "GSHB/SAMBA/netlogon", value:"error");
  set_kb_item(name: "GSHB/SAMBA/smbpasswd", value:"error");
  set_kb_item(name: "GSHB/SAMBA/secretstdb", value:"error");
  set_kb_item(name: "GSHB/SAMBA/log", value:error);
  exit(0);
}

windowstest = ssh_cmd(socket:sock, cmd:"cmd /?");
if (("windows" >< windowstest && "interpreter" >< windowstest) || ("Windows" >< windowstest && "interpreter" >< windowstest)){
#  set_kb_item(name: "GSHB/SAMBA/conf", value:"windows");
  set_kb_item(name: "GSHB/SAMBA/global", value:"windows");
  set_kb_item(name: "GSHB/SAMBA/netlogon", value:"windows");
  set_kb_item(name: "GSHB/SAMBA/smbpasswd", value:"windows");
  set_kb_item(name: "GSHB/SAMBA/secretstdb", value:"windows");
  exit(0);
}

smbpasswd = ssh_cmd(socket:sock, cmd:"ls -l /etc/smbpasswd");
secretstdb = ssh_cmd(socket:sock, cmd:"ls -l /var/lib/samba/secrets.tdb");
smbconf = ssh_cmd(socket:sock, cmd:"egrep -v '^(#|;)' /etc/samba/smb.conf");
if (smbconf =~ ".*(Datei oder Verzeichnis nicht gefunden|No such file or directory).*") smbconf = "none";
if (smbpasswd =~ ".*(Datei oder Verzeichnis nicht gefunden|No such file or directory).*") smbpasswd = "none";
if (secretstdb =~ ".*(Datei oder Verzeichnis nicht gefunden|No such file or directory).*") secretstdb = "none";

if (smbconf != "none"){
  Lst = split(smbconf, keep:FALSE);
  for(i=0; i<max_index(Lst); i++){
    if (Lst[i] == "") continue;
    val += Lst[i] + '\n';
  }
  if (!val) smbconf = "novalentrys";
  else smbconf = val;
}

if (smbconf == "none") global = "none";
else if (smbconf != "none" && smbconf != "novalentrys"){
  val = eregmatch(string:smbconf, pattern:"global.*]", icase:FALSE);
  Lst = split(val[0], keep:FALSE);
  for(i=1; i<max_index(Lst); i++){
    if ("[" >< Lst[i]) i = 999999;
    else global += Lst[i] + '\n';
  }
  if (!global) global = "novalentrys";
}

if (smbconf == "none") netlogon = "none";
else if (smbconf != "none" && smbconf != "novalentrys"){
  val = eregmatch(string:smbconf, pattern:"netlogon.*]", icase:FALSE);
  Lst = split(val[0], keep:FALSE);
  for(i=1; i<max_index(Lst); i++){
    if ("[" >< Lst[i]) i = 999999;
    else netlogon += Lst[i] + '\n';
  }
  if (!netlogon) netlogon = "novalentrys";
}

#set_kb_item(name: "GSHB/SAMBA/conf", value:smbconf);
set_kb_item(name: "GSHB/SAMBA/global", value:global);
set_kb_item(name: "GSHB/SAMBA/netlogon", value:netlogon);
set_kb_item(name: "GSHB/SAMBA/smbpasswd", value:smbpasswd);
set_kb_item(name: "GSHB/SAMBA/secretstdb", value:secretstdb);

exit(0);
