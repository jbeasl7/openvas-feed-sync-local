# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150083");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-01-16 09:19:53 +0100 (Thu, 16 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: SSH DenyUsers");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_sshd_config.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"user1 user2", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/5/sshd_config");

  script_tag(name:"summary", value:"The DenyUsersvariable gives the system administrator the option of denying
  specific users to ssh into the system. The list consists of space separated user names. Numeric
  user IDs are not recognized with this variable. If a system administrator wants to restrict user
  access further by specifically denying a user's access from a particular host, the entry can be
  specified in the form of user@host.");

  exit(0);
}

include("policy_functions.inc");

cmd = "grep '^DenyUsers' /etc/ssh/sshd_config";
title = "SSH DenyUsers";
solution = "Edit /etc/ssh/sshd_config and run 'service sshd restart'";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("linux/mount/ERROR")){
  test_type = "Manual Check";
  value = "Error";
  compliant = "incomplete";
  comment = "Could not read /etc/ssh/sshd_config";
}else{
  sshd_config = get_kb_item("Policy/linux/sshd_config");
  grep = egrep(icase:TRUE, pattern:"^DenyUsers", string:sshd_config);
  match = eregmatch(string:grep, pattern:'DenyUsers\\s+([^\n\r]+)');
  value = match[1];
  compliant = policy_settings_lists_match(value:value, set_points:default, sep:" ");
  comment = "";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);