# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150177");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-03-23 10:57:29 +0000 (Mon, 23 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: SINGLE in /etc/sysconfig/init");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_etc_sysconfig_init.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"/sbin/sulogin", id:1);

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/my/doc/EDOC1000109487/6c55c764/hardening-the-single-user-mode");

  script_tag(name:"summary", value:"The single-user mode enters with root access. If you do not set
password-protect, there will be serious security risks.");

  exit(0);
}

include("policy_functions.inc");

cmd = "grep 'SINGLE' /etc/sysconfig/init";
title = "SINGLE in /etc/sysconfig/init";
solution = "Add or remove 'SINGLE=VALUE' to /etc/sysconfig/init";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/linux/sysctl/conf/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/linux//etc/sysconfig/init/content/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not read /etc/sysconfig/init";
}else{
  content = get_kb_item("Policy/linux//etc/sysconfig/init/content");
  grep = egrep(string:content, pattern:"SINGLE");

  if(grep =~ "^\s*#"){
    value = "None";
  }else{
    match = eregmatch(string:chomp(grep), pattern:"SINGLE\s*=\s*(.+)");
    if(match)
      value = match[1];
    else
      value = "None";
  }
  compliant = policy_setting_exact_match(value:value, set_point:default);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
