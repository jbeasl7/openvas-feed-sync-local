# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150171");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-03-17 15:31:22 +0000 (Tue, 17 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: rsyslog status");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_and_parse_systemctl_list_units.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://linux.die.net/man/8/rsyslogd");

  script_add_preference(name:"Value", type:"radio", value:"enabled;disabled;status;indirect", id:1);

  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 4.2.1.2 Ensure rsyslog Service is enabled (Scored)");
  script_xref(name:"Policy", value:"CIS CentOS Linux 8 Benchmark v1.0.0: 4.2.1.2 Ensure rsyslog Service is enabled (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 6.3 Enable Detailed Logging");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 6.2 Activate audit logging");

  script_tag(name:"summary", value:"Rsyslogd is a system utility providing support for message
logging. Support of both internet and unix domain sockets enables this utility to support both local
and remote logging.");

  exit(0);
}

include("policy_functions.inc");

cmd = "systemctl is-enabled rsyslog";
title = "Status of rsyslog";
solution = "Run 'systemctl OPTION rsyslog";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/linux/systemctl/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/linux/systemctl/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not run systemctl";
}else{
  if(!value = get_kb_item("Policy/linux/systemctl/rsyslog/service"))
    value = "Not found";

  compliant = policy_setting_exact_match(value:value, set_point:default);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
