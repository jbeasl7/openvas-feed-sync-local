# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.116485");
  script_version("2025-01-22T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"creation_date", value:"2023-03-21 08:00:00 +0000 (Tue, 21 Mar 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: SSH AuthenticationMethods and RequiredAuthentications");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_sshd_config.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"publickey", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/5/sshd_config");
  script_xref(name:"URL", value:"https://man7.org/linux/man-pages/man5/sshd_config.5.html");

  script_tag(name:"summary", value:"sshd reads configuration data from /etc/ssh/sshd_config (or the
file specified with -f on the command line). The file contains keyword-argument pairs, one per line.
Lines starting with '#' and empty lines are interpreted as comments. Arguments may optionally be
enclosed in double quotes in order to represent arguments containing spaces.

AuthenticationMethods or RequiredAuthentications specifies the authentication methods that must be
successfully completed for a user to be granted access");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = "grep '^AuthenticationMethods' /etc/ssh/sshd_config";
cmd2 = "grep '^RequiredAuthentications' /etc/ssh/sshd_config";
title = "SSH AuthenticationMethods and RequiredAuthentications";
solution = "Edit /etc/ssh/sshd_config";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);
value = get_kb_item("Policy/linux/sshd_config/authenticationmethods");
value2 = get_kb_item("Policy/linux/sshd_config/requiredauthentications");

if(get_kb_item("Policy/linux/sshd_config/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not read /etc/ssh/sshd_config";
}else if(!value && !value2){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not find configurations in /etc/ssh/sshd_config";
}else{
  if(value =~ "publickey" || value2 =~ "publickey"){
    compliant = "yes";
  }else{
    compliant = "no";
  }
}

policy_reporting(result:value + '\n' + value2, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd + '\n' + cmd2, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
