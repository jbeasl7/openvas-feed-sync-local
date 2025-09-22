# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109760");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-01-24 10:47:10 +0100 (Thu, 24 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Log Martians packets");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_etc_sysctl_d.nasl", "read_and_parse_sysctl.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://linux.die.net/man/5/sysctl.conf");
  script_xref(name:"URL", value:"https://www.cyberciti.biz/faq/linux-kernel-etcsysctl-conf-security-hardening/");

  script_add_preference(name:"Status", type:"radio", value:"Enabled;Disabled", id:1);

  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 3.2.4 Ensure suspicious packets are logged (Scored)");
  script_xref(name:"Policy", value:"CIS CentOS Linux 8 Benchmark v1.0.0: 3.2.4 Ensure suspicious packets are logged (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 6.3 Enable Detailed Logging");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 6.2 Activate audit logging");

  script_tag(name:"summary", value:"Martian packets are packets with an obviously wring source
address. These packets can not be routed over the network. An attacker can use those packets, e.g.
for a DoS/DDoS attack. Logging those packets can help for further inspections.

This script tests whether the Linux host is configured to log Martians packets.");

  exit(0);
}

include("policy_functions.inc");

cmd = "sysctl net.ipv4.conf.all.log_martians, sysctl net.ipv4.conf.default.log_martians";
title = "Log suspicious packets";
solution = "Set the parameters in /etc/sysctl.conf or a /etc/sysctl.d/* file and run 'sysctl -w SETTING = VALUE'";
test_type = "SSH_Cmd";
default = script_get_preference("Status", id:1);

if(get_kb_item("Policy/linux/sysctl/conf/ERROR") ||
   get_kb_item("Policy/linux/sysctl/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/linux//etc/sysctl.conf/content/ERROR") ||
         get_kb_item("Policy/linux/sysctl/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not read /etc/sysctl.conf or run sysctl";
}else{
  sysctl_d_files = get_kb_list("Policy/linux//etc/sysctl.d/*/content");
  content_list = make_list(sysctl_d_files, get_kb_item("Policy/linux//etc/sysctl.conf/content"));

  foreach content (content_list){
    if(content =~ "net\.ipv4\.conf\.all\.log_martians\s*=\s*1" ||
       content =~ "net\.ipv4\.conf\.default\.log_martians\s*=\s*1"){
      value = "Enabled";
    }
  }

  net_ipv4_conf_all_log_martians = get_kb_item("Policy/linux/sysctl/net.ipv4.conf.all.log_martians");
  net_ipv4_conf_default_log_martians = get_kb_item("Policy/linux/sysctl/net.ipv4.conf.default.log_martians");

  if( net_ipv4_conf_all_log_martians != "0" ||
      net_ipv4_conf_default_log_martians != "0"){
    value = "Enabled";
  }

  if(!value)
    value = "Disabled";

  compliant = policy_setting_exact_match(value:value, set_point:default);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
