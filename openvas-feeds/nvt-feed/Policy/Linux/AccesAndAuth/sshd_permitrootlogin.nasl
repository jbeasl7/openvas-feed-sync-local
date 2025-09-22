# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150072");
  script_version("2023-09-22T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-09-22 05:05:30 +0000 (Fri, 22 Sep 2023)");
  script_tag(name:"creation_date", value:"2020-01-14 14:14:36 +0100 (Tue, 14 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: SSH PermitRootLogin");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_sshd_config.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"no;yes;prohibit-password;forced-commands-only", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/5/sshd_config");
  script_xref(name:"Policy", value:"CIS Ubuntu Linux 20.04 v2.0.0: 4.2.8 Ensure SSH root login is disabled (Automated)");
  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 5.2.10 Ensure SSH root login is disabled (Scored)");
  script_xref(name:"Policy", value:"CIS CentOS Linux 8 Benchmark v1.0.0: 5.2.10 Ensure SSH root login is disabled (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 4.3 Ensure the Use of Dedicated Administrative Accounts");

  script_tag(name:"summary", value:"The PermitRootLoginparameter specifies if the root user can log in using ssh.
  The default is no.

  Note: If disabling and not using root for scanning, ensure the scanning account has appropriate
  permissions for scanning.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = "grep '^PermitRootLogin' /etc/ssh/sshd_config";
title = "SSH PermitRootLogin";
solution = "Edit the /etc/ssh/sshd_config file to set the parameter as follows:
PermitRootLogin no";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/linux/sshd_config/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not read /etc/ssh/sshd_config";
}else{
  value = get_kb_item("Policy/linux/sshd_config/permitrootlogin");
  compliant = policy_setting_exact_match(value:value, set_point:default);
  comment = "";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
