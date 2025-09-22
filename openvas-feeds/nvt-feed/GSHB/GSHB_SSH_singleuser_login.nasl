# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96078");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-09 15:04:43 +0200 (Fri, 09 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Read /etc/inittab, /etc/init/rcS.conf and /etc/event.d/rcS-sulogin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"This plugin uses ssh to Read /etc/inittab, /etc/init/rcS.conf and /etc/event.d/rcS-sulogin.");

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
    set_kb_item(name: "GSHB/inittab", value:"error");
    set_kb_item(name: "GSHB/rcSconf", value:"error");
    set_kb_item(name: "GSHB/rcSsulogin", value:"error");
    set_kb_item(name: "GSHB/inittab/log", value:error);
    exit(0);
}

windowstest = ssh_cmd(socket:sock, cmd:"cmd /?");
if (("windows" >< windowstest && "interpreter" >< windowstest) || ("Windows" >< windowstest && "interpreter" >< windowstest)){
    set_kb_item(name: "GSHB/inittab", value:"windows");
    set_kb_item(name: "GSHB/rcSconf", value:"windows");
    set_kb_item(name: "GSHB/rcSsulogin", value:"windows");
  exit(0);
}

inittab = ssh_cmd(socket:sock, cmd:"LANG=C cat /etc/inittab");
rcSconf = ssh_cmd(socket:sock, cmd:"LANG=C cat /etc/init/rcS.conf");
rcSsulogin = ssh_cmd(socket:sock, cmd:"LANG=C cat /etc/event.d/rcS-sulogin");

if ("cat: command not found" >< inittab) inittab = "nocat";
if ("cat: command not found" >< rcSconf) rcSconf = "nocat";
if ("cat: command not found" >< rcSsulogin) rcSsulogin = "nocat";

if ("cat: /etc/inittab: Permission denied" >< inittab) inittab = "noperm";
else if (inittab =~ '.*o such file or directory.*') inittab = "none";

if ("cat: /etc/init/rcS.conf: Permission denied" >< rcSconf) rcSconf = "noperm";
else if (rcSconf =~ '.*o such file or directory.*') rcSconf = "none";

if ("cat: /etc/event.d/rcS-sulogin: Permission denied" >< rcSsulogin) initrcSsulogintab = "noperm";
else if (rcSsulogin =~ '.*o such file or directory.*') rcSsulogin = "none";


if("none" >!< inittab && "noperm" >!< inittab){
  inittabS = egrep(string:inittab, pattern:"(.){1,4}:S:.*:.*", icase:1);

  inittab1 = egrep(string:inittab, pattern:"(.){1,4}:1:.*:.*", icase:1);
  if (inittabS == "") inittabS = "none";
  if (inittab1 == "") inittab1 = "none";
  set_kb_item(name: "GSHB/inittab", value:1);
  set_kb_item(name: "GSHB/inittabS", value:inittabS);
  set_kb_item(name: "GSHB/inittab1", value:inittab1);
}else{
  set_kb_item(name: "GSHB/inittab", value:inittab);
  set_kb_item(name: "GSHB/inittabS", value:"none");
  set_kb_item(name: "GSHB/inittab1", value:"none");
}

if("none" >!< rcSconf && "noperm" >!< rcSconf){
  rcSconfwrong = egrep(string:rcSconf, pattern:"exec /bin/bash", icase:0);
  rcSconfright = egrep(string:rcSconf, pattern:"exec /sbin/sulogin", icase:0);

  if(rcSconfwrong != "") rcSconf = "wrong:" + rcSconfwrong;
  else if(rcSconfright != "") rcSconf = "right:" + rcSconfright;
  else if((rcSconfright == "" && rcSconfwrong == "") || (rcSconfright != "" && rcSconfwrong != "")) rcSconf = "unknown:" + rcSconfright + rcSconfwrong;
}

if("none" >!< rcSsulogin && "noperm" >!< rcSsulogin){
  rcSsuloginwrong = egrep(string:rcSsulogin, pattern:"exec /bin/bash", icase:0);
  rcSsuloginright = egrep(string:rcSsulogin, pattern:"exec /sbin/sulogin", icase:0);

  if(rcSsuloginwrong != "") rcSsulogin = "wrong:" + rcSsuloginwrong;
  else if(rcSsuloginright != "") rcSsulogin = "right:" + rcSsuloginright;
  else if((rcSsuloginright == "" && rcSsuloginwrong == "") || (rcSsuloginright != "" && rcSsuloginwrong != "")) rcSsulogin = "unknown:" + rcSsuloginright + ":" + rcSsuloginwrong;
}


set_kb_item(name: "GSHB/rcSconf", value:rcSconf);
set_kb_item(name: "GSHB/rcSsulogin", value:rcSsulogin);

exit(0);



