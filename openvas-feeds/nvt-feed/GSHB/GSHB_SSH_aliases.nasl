# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96067");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("List /etc/aliases");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"This plugin uses ssh to List /etc/aliases.");

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
    set_kb_item(name: "GSHB/Aliasesrights", value:"error");
    set_kb_item(name: "GSHB/Aliasescont", value:"error");
    set_kb_item(name: "GSHB/Aliasescont/log", value:error);
    exit(0);
}

windowstest = ssh_cmd(socket:sock, cmd:"cmd /?");
if (("windows" >< windowstest && "interpreter" >< windowstest) || ("Windows" >< windowstest && "interpreter" >< windowstest)){
  set_kb_item(name: "GSHB/Aliasesrights", value:"windows");
  set_kb_item(name: "GSHB/Aliasescont", value:"windows");
  exit(0);
}


aliasesrights = ssh_cmd(socket:sock, cmd:"ls -l cat /etc/aliases");
if ("ls: " >< aliasesrights) aliasesrights = "noaliases";
if (!aliasesrights) aliasesrights = "noaliases";
else{
  val = split(aliasesrights, sep:" ",keep:0);
  aliasesrights = val[0] + " " + val[2] + " " + val[3];
}

aliasescont = ssh_cmd(socket:sock, cmd:"cat /etc/aliases");
if ("cat: /etc/aliases:" >< aliasescont) aliasescont = "noaliases";
if (!aliasescont) aliasescont = "noaliases";

set_kb_item(name: "GSHB/Aliasesrights", value:aliasesrights);
set_kb_item(name: "GSHB/Aliasescont", value:aliasescont);
exit(0);
