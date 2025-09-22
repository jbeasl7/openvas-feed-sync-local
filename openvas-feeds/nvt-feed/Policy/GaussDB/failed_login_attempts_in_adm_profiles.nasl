# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150208");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-04-09 12:25:50 +0000 (Thu, 09 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("ZSQL: Number of Failed Login Attempts");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "zsql_adm_profiles.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"10", id:1);

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");
  script_tag(name:"summary", value:"The FAILED_LOGIN_ATTEMPTS parameter specifies the maximum number
of login attempts allowed before an account is locked. If the number of an account's login failures
exceeds the value of this parameter, the system automatically locks the account. The default value
is 10.");

  exit(0);
}

include("policy_functions.inc");

cmd = "SELECT RESOURCE_NAME, THRESHOLD FROM ADM_PROFILES WHERE RESOURCE_NAME='FAILED_LOGIN_ATTEMPTS';";
title = "Number of Failed Login Attempts";
solution = "ALTER PROFILE profile_name LIMIT FAILED_LOGIN_ATTEMPTS 10;";
test_type = "SQL_Query";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/zsql/adm_profiles/ssh/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/zsql/adm_profiles/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "Can not read table adm_profiles";
}else if(!value = get_kb_item("Policy/zsql/adm_profiles/FAILED_LOGIN_ATTEMPTS/threshold")){
  compliant = "incomplete";
  value = "error";
  comment = "Can not find value for FAILED_LOGIN_ATTEMPTS in table adm_profiles";
}else{
  compliant = policy_setting_max_match(value:value, set_point:default);
}

policy_reporting(result:value, default:"<= " + default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);

policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
