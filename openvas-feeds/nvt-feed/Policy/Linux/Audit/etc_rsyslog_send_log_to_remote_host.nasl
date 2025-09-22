# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150164");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-03-13 08:35:44 +0000 (Fri, 13 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: send logs to a remote log host in /etc/rsyslog.conf");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_etc_rsyslog_conf.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"@@loghost.example.com", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/5/rsyslog.conf");

  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 4.2.1.5 Ensure rsyslog is configured to send logs to a remote log host (Scored)");
  script_xref(name:"Policy", value:"CIS CentOS Linux 8 Benchmark v1.0.0: 4.2.1.5 Ensure rsyslog is configured to send logs to a remote log host (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 6.8 Regularly Tune SIEM");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 6.6 Deploy SIEM or Log Analytic tool");

  script_tag(name:"summary", value:"There are three ways to forward message: the traditional UDP
transport, which is extremely lossy but standard, the plain TCP based transport which loses
messages only during certain situations but is widely available and the RELP transport which does
not lose messages but is currently available only as part of rsyslogd 3.15.0 and above.");

  exit(0);
}

include("policy_functions.inc");

cmd = "grep '^*.*[^I][^I]*@' /etc/rsyslog.conf";
title = "Send logs to a remote log host";
solution = "Edit the /etc/rsyslog.conf and /etc/rsyslog.d/*.conf files and add the following line
(where loghost.example.com is the name of your central log host).

*.* @@loghost.example.com

Run the following command to reload the rsyslogd configuration:

# systemctl restart rsyslog";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/linux//etc/rsyslog.conf/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/linux//etc/rsyslog.conf/content/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not read /etc/rsyslog.conf";
}else{
  content = get_kb_item("Policy/linux//etc/rsyslog.conf/content");
  value = chomp(egrep(string:content, pattern:"^[^#]*\*\.\*\s+@"));

  if(value){
    compliant = "yes";
    if(default >< value){
      comment = "Specified log host found.";
    }else{
      comment = "Verify the value manually.";
    }
  }else{
    value = "None";
    compliant = "no";
    comment = "Did not find any remote server in /etc/rsyslog.conf";
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
