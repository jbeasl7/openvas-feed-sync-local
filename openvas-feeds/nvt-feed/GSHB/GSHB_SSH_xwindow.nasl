# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96077");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-06-02 09:25:45 +0200 (Wed, 02 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Check if X11 tunnel in sshd_config is enabled, list 'xhost' rights");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"This plugin uses ssh to Check if X11 tunnel in sshd_config is enabled, list 'xhost' rights.");

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
    set_kb_item(name: "GSHB/xwindow/sshd", value:"error");
#    set_kb_item(name: "GSHB/xwindow/xhost", value:"error");
    set_kb_item(name: "GSHB/xwindow/lsxhost", value:"error");
    set_kb_item(name: "GSHB/xwindow/log", value:error);
    exit(0);
}

windowstest = ssh_cmd(socket:sock, cmd:"cmd /?");
if (("windows" >< windowstest && "interpreter" >< windowstest) || ("Windows" >< windowstest && "interpreter" >< windowstest)){
    set_kb_item(name: "GSHB/xwindow/sshd", value:"windows");
#    set_kb_item(name: "GSHB/xwindow/xhost", value:"windows");
    set_kb_item(name: "GSHB/xwindow/lsxhost", value:"windows");
  exit(0);
}

sshd_config = ssh_cmd(socket:sock, cmd:"LANG=C grep -i X11Forwarding /etc/ssh/sshd_config");
#xhost = ssh_cmd(socket:sock, cmd:"xhost");
lsxhost = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /usr/bin/xhost");

if ("No such file or directory" >< lsxhost){
  lsxhost = "noxhost";
}else{
  lsxhost = split(lsxhost, sep:" ", keep:1);
  lsxhost = lsxhost[0] + lsxhost[2] + lsxhost[3];
}

if ("grep: command not found" >< sshd_config) sshd_config = "nogrep";
#if ("xhost: command not found" >< xhost) xhost = "noxhost";
if ("grep: /etc/ssh/sshd_config: Permission denied" >< sshd_config) sshd_config = "noperm";
else if ("grep: /etc/ssh/sshd_config:" >< sshd_config) sshd_config = "none";

set_kb_item(name: "GSHB/xwindow/sshd", value:sshd_config);
#set_kb_item(name: "GSHB/xwindow/xhost", value:xhost);
set_kb_item(name: "GSHB/xwindow/lsxhost", value:lsxhost);
exit(0);



