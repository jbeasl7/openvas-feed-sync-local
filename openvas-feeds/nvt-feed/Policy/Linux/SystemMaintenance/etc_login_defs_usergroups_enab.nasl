# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150139");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-02-19 13:48:00 +0000 (Wed, 19 Feb 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: USERGROUP_ENAB in /etc/login.defs");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_etc_login_defs.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"Yes;No", id:1);

  script_xref(name:"URL", value:"http://www.man7.org/linux/man-pages/man1/su.1.html");

  script_tag(name:"summary", value:"su allows to run commands with a substitute user and group ID.

When called with no user specified, su defaults to running an interactive shell as root. When user
is specified, additional arguments can be supplied, in which case they are passed to the shell.

USERGROUPS_ENAB enables setting of the umask group bits to be the same as owner bits (examples: 022 -> 002,
077 -> 007) for non-root users, if the uid is the same as gid, and username is the same as
the primary group name.");
  exit(0);
}

include("policy_functions.inc");

cmd = "grep '^USERGROUPS_ENAB' /etc/login.defs";
title = "USERGROUPS_ENAB in /etc/login.defs";
solution = "Add or modify 'USERGROUPS_ENAB' to /etc/login.defs";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);
default = "Yes";

if(get_kb_item("Policy/linux//etc/login.defs/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/linux//etc/login.defs/content/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not read /etc/login.defs";
}else{
  content = get_kb_item("Policy/linux//etc/login.defs/content");
  foreach line (split(content, keep:FALSE)){
    match = eregmatch(string:line, pattern:"^\s*USERGROUPS_ENAB\s*(.+)$");
    if(match)
      value = match[1];
  }

  if(!value)
    value = "No";

  compliant = policy_setting_exact_match(value:tolower(value), set_point:tolower(default));
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
