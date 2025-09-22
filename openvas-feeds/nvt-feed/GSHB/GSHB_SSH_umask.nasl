# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96068");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("List an Verify umask entries in /etc/profile and ~/.profile");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"This plugin uses ssh to List an Verify umask entries in /etc/profile and ~/.profile.");

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
    set_kb_item(name: "GSHB/umask", value:"error");
    set_kb_item(name: "GSHB/umask/log", value:error);
    exit(0);
}

etcprofile = ssh_cmd(socket:sock, cmd:"cat /etc/profile");
if (!etcprofile){
    set_kb_item(name: "GSHB/umask", value:"error");
    set_kb_item(name: "GSHB/umask/log", value:"/etc/profile was not found");
    exit(0);
}

etcprofileumask = egrep(string:etcprofile, pattern:"umask [0-7]{3,4}");
if (etcprofileumask !~ "(u|U)(M|m)(A|a)(S|s)(K|k) 0027" && etcprofileumask !~ "(u|U)(M|m)(A|a)(S|s)(K|k) 0077") etcbit = "fail";
else etcbit = "pass";

UsProfLst = ssh_cmd(socket:sock, cmd:"locate /home/*/.profile");
if("command not found" >< UsProfLst) UsProfLst = ssh_cmd(socket:sock, cmd:"find /home -name .profile -type f -print");

if ("FIND: Invalid switch" >< UsProfLst|| "FIND: Parameterformat falsch" >< UsProfLst){
  set_kb_item(name: "GSHB/umask", value:"windows");
  exit(0);
}


if(UsProfLst) {
  spList = split(UsProfLst, keep:0);
  for(i=0; i<max_index(spList); i++){
    usrname = split(spList[i], sep:"/", keep:0);
    a = max_index(usrname) - 2;
    usrname = usrname[a];
    usrprofile = ssh_cmd(socket:sock, cmd:"cat " + spList[i]);
    usrprofileumask = egrep(string:usrprofile, pattern:"umask [0-7]{3,4}");
    if ("#" >!< usrprofileumask){
          if (usrprofileumask !~ "(u|U)(M|m)(A|a)(S|s)(K|k) 0027" && usrprofileumask !~ "(u|U)(M|m)(A|a)(S|s)(K|k) 0077") failuser += "User: " + usrname + ", File: "+ spList[i] + "=" + usrprofileumask;
    }else usrbit = "noconf";
  }
}else usrbit = "noconf";

if (etcbit == "fail" && usrbit == "noconf") umaskfail = "1";
if (etcbit == "pass" && failuser) umaskfail = "1";
if (umaskfail == "1"){
  if (etcbit == "pass" && failuser) result = failuser;
  else if (etcbit == "fail" && usrbit == "noconf" && failuser) result = "/etc/profile = " + etcprofileumask + failuser;
  else result = "/etc/profile=" + etcprofileumask;
}else result = "none";

set_kb_item(name: "GSHB/umask", value:result);
exit(0);
