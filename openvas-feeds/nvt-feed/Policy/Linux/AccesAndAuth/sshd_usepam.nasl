# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150227");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-05-07 06:49:26 +0000 (Thu, 07 May 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: SSH UsePAM");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_sshd_config.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"yes;no", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/5/sshd_config");
  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 5.2.20 Ensure SSH PAM is enabled (Scored)");
  script_xref(name:"Policy", value:"CIS CentOS Linux 8 Benchmark v1.0.0: 5.2.16 Ensure SSH PAM is enabled (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 5.1 Establish Secure Configurations");

  script_tag(name:"summary", value:"UsePAM Enables the Pluggable Authentication Module interface. If set to 'yes'
  this will enable PAM authentication using ChallengeResponseAuthentication and
  PasswordAuthentication in addition to PAM account and session module processing for all
  authentication types.

  When usePAM is set to yes, PAM runs through account and session types properly. This is important
  if you want to restrict access to services based off of IP, time or other factors of the account.
  Additionally, you can make sure users inherit certain environment variables on login or disallow
  access to the server.");

  exit(0);
}

include("policy_functions.inc");

cmd = "grep '^UsePAM' /etc/ssh/sshd_config";
title = "SSH UsePAM";
solution = "Edit the /etc/ssh/sshd_config file to set the parameter as follows:
UsePAM yes";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("linux/mount/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not read /etc/ssh/sshd_config";
}else{
  value = get_kb_item("Policy/linux/sshd_config/usepam");
  compliant = policy_setting_exact_match(value:value, set_point:default);
  comment = "";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);