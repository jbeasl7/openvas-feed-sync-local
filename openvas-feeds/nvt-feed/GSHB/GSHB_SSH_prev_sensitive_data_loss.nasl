# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96080");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-13 14:21:58 +0200 (Tue, 13 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Check accessrights of ps, finger, who, last and /var/log/?tmp*");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"This plugin uses ssh to Check accessrights of ps, finger, who, last and /var/log/?tmp*.

  Check if ps, finger, who and last is not user executable, check perm 660 for /var/log/?tmp*");

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
    set_kb_item(name: "GSHB/ps", value:"error");
    set_kb_item(name: "GSHB/finger", value:"error");
    set_kb_item(name: "GSHB/who", value:"error");
    set_kb_item(name: "GSHB/last", value:"error");
    set_kb_item(name: "GSHB/tmpfiles", value:"error");
    set_kb_item(name: "GSHB/ps/log", value:error);
    exit(0);
}

windowstest = ssh_cmd(socket:sock, cmd:"cmd /?");
if (("windows" >< windowstest && "interpreter" >< windowstest) || ("Windows" >< windowstest && "interpreter" >< windowstest)){
    set_kb_item(name: "GSHB/ps", value:"windows");
    set_kb_item(name: "GSHB/finger", value:"windows");
    set_kb_item(name: "GSHB/who", value:"windows");
    set_kb_item(name: "GSHB/last", value:"windows");
    set_kb_item(name: "GSHB/tmpfiles", value:"windows");
  exit(0);
}


ps = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /bin/ps");
finger = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /usr/bin/finger");
who = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /usr/bin/who");
last = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /usr/bin/last");
tmpfiles = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /var/log/?tmp*");

if (ps =~ ".*such.file.*directory") ps = "none";
else if (!ps) ps = "none";
else{
  Lst = split(ps, sep:" ", keep:0);
  ps = Lst[0] + ":" + Lst[2] + ":"  + Lst[3];
}

if (finger =~ ".*such.file.*directory") finger = "none";
else if (!finger) finger = "none";
else{
  Lst = split(finger, sep:" ", keep:0);
  finger = Lst[0] + ":" + Lst[2] + ":"  + Lst[3];
}

if (who =~ ".*such.file.*directory") who = "none";
else if (!who) who = "none";
else{
  Lst = split(who, sep:" ", keep:0);
  who = Lst[0] + ":" + Lst[2] + ":"  + Lst[3];
}

if (last =~ ".*such.file.*directory") last = "none";
else if (!last) last = "none";
else{
  Lst = split(last, sep:" ", keep:0);
  last = Lst[0] + ":" + Lst[2] + ":"  + Lst[3];
}

if (tmpfiles =~ ".*such.file.*directory") tmpfiles = "none";
else if (!tmpfiles) tmpfiles = "none";
else{
  Lst = split(tmpfiles, keep:0);
  tmpfiles = "";
  for (i=0; i<max_index(Lst); i++){
    tmpLst = split(Lst[i], sep:" ", keep:0);
    tmpfiles += tmpLst[0] + ":" + tmpLst[2] + ":"  + tmpLst[3] + ":" + tmpLst[max_index(tmpLst)-1] +'\n';
  }
}

set_kb_item(name: "GSHB/ps", value:ps);
set_kb_item(name: "GSHB/finger", value:finger);
set_kb_item(name: "GSHB/who", value:who);
set_kb_item(name: "GSHB/last", value:last);
set_kb_item(name: "GSHB/tmpfiles", value:tmpfiles);
exit(0);
