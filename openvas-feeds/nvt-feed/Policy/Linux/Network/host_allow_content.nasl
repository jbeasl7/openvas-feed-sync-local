# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150087");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-01-20 09:10:10 +0100 (Mon, 20 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: /etc/hosts.allow content");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_etc_hosts_allow.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://linux.die.net/man/5/hosts_access");

  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 3.3.2 Ensure /etc/hosts.allow is configured (Not Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 9.4 Apply Host-based Firewalls or Port Filtering");

  script_tag(name:"summary", value:"The access control software consults two files. The search stops
at the first match:

  - Access will be granted when a (daemon, client) pair matches an entry in the /etc/hosts.allow file.

  - Otherwise, access will be denied when a (daemon, client) pair matches an entry in the /etc/hosts.deny file.

  - Otherwise, access will be granted.

A non-existing access control file is treated as if it were an empty file. Thus, access control can
be turned off by providing no access control files.

Note: This script shows the content of /etc/hosts.allow file only.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = "cat /etc/hosts.allow";
title = "/etc/hosts.allow content";
solution = "Configure /etc/hosts.allow";
test_type = "SSH_Cmd";

if(get_kb_item("Policy/linux/etc/hosts_allow/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not read /etc/hosts.allow";
}else{
  value = get_kb_item("Policy/linux/etc/hosts_allow");
  compliant = "yes";
  comment = "";
}

policy_reporting(result:value, default:"None", compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:"None", solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
