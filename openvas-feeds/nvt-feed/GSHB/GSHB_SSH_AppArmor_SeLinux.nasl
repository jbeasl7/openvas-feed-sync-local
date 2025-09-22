# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109039");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-01-02 10:56:23 +0200 (Tue, 02 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Test existence of App-Armor, SeLinux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"This script checks the existence of App-Armor
  and SeLinux on a Linux host.");

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = get_preference("auth_port_ssh");
if(!port)
  port = ssh_get_port(default:22, ignore_unscanned:TRUE);

sock = ssh_login_or_reuse_connection();
if( !sock ) {
    error = ssh_get_error();
    if ( !error ) error = "No SSH Port or Connection!";
    log_message(port:port, data:error);
    set_kb_item(name:"GSHB/AppArmor_SeLinux", value:"error");
    exit(0);
}

windowstest = ssh_cmd(socket:sock, cmd:"cmd /?");
if( "windows" >< tolower(windowstest) && "interpreter" >< windowstest ){
  set_kb_item(name:"GSHB/AppArmor_SeLinux", value:"windows");
  exit(0);
}

cmd = 'dpkg -s apparmor';
AppArmorB = ssh_cmd(socket:sock, cmd:cmd);
AppArmor_Basic = ereg(string:AppArmorB, pattern:'package: apparmor.+status: install ok installed', icase: TRUE, multiline:TRUE);
cmd = 'dpkg -s apparmor-utils';
AppArmorU = ssh_cmd(socket:sock, cmd:cmd);
AppArmor_Utils = ereg(string:AppArmorU, pattern:'package: apparmor-utils.+status: install ok installed', icase:TRUE, multiline:TRUE);

if( AppArmor_Basic == "1" ) {
  set_kb_item(name:"GSHB/AppArmor_Basic", value:"1");
}else{
  set_kb_item(name:"GSHB/AppArmor_Basic", value:"0");
}

if( AppArmor_Utils != '1' ){
  set_kb_item(name:"GSHB/AppArmor_Utils", value:"0");
}else{
  set_kb_item(name:"GSHB/AppArmor_Utils", value:"1");
  cmd = '/usr/sbin/aa-status';
  apparmor_status = ssh_cmd(socket:sock, cmd:cmd);
  if( "no such file or directory" >< tolower(apparmor_status) || ! apparmor_status ||
      "command not found" >< tolower(apparmor_status) ){
    set_kb_item(name:"GSHB/AppArmor_Status", value:"error");
  }else{
    set_kb_item(name:"GSHB/AppArmor_Status", value:apparmor_status);
  }
}

cmd = 'dpkg -s selinux-basics';
SELinuxB = ssh_cmd(socket:sock, cmd:cmd);
cmd = 'dpkg -s selinux-utils';
SELinuxU = ssh_cmd(socket:sock, cmd:cmd);
SELinux_Basics = ereg(string:SELinuxB, pattern:'package: selinux-basics.+status: install ok installed', icase:TRUE, multiline:TRUE);
SELinux_Utils = ereg(string:SELinuxU, pattern:'package: selinux-utils.+status: install ok installed', icase:TRUE, multiline:TRUE);
if( SELinux_Basics == '1' ){
  set_kb_item(name:"GSHB/SeLinux_Basics", value:"1");
}else{
  set_kb_item(name:"GSHB/SeLinux_Basics", value:"0");
}

if( SELinux_Utils != '1' ){
  set_kb_item(name:"GSHB/SeLinux_Utils", value:"0");
}else{
  set_kb_item(name:"GSHB/SeLinux_Utils", value:"1");
  cmd = '/usr/sbin/sestatus -b';
  sestatus = ssh_cmd(socket:sock, cmd:cmd);
  if( ! sestatus || "command not found" >< tolower(sestatus) ||
      "no such file or directory" >< tolower(sestatus) ){
    set_kb_item(name:"GSHB/SeLinux_Status", value:"error");
  }else{
    set_kb_item(name:"GSHB/SeLinux_Status", value:sestatus);
  }
}

exit(0);
