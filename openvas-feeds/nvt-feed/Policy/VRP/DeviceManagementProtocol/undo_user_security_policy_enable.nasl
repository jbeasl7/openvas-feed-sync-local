# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150294");
  script_version("2024-05-24T19:38:34+0000");
  script_tag(name:"last_modification", value:"2024-05-24 19:38:34 +0000 (Fri, 24 May 2024)");
  script_tag(name:"creation_date", value:"2020-07-14 07:00:38 +0000 (Tue, 14 Jul 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Huawei Data Communication: Configuring User Password Complexity Check");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "vrp_current_configuration.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("huawei/vrp/yunshan/detected");

  script_tag(name:"summary", value:"The system checks the password complexity when setting a user
password.");

  exit(0);
}

include("policy_functions.inc");

major_version = get_kb_item("huawei/vrp/ssh-login/major_version");

port = get_kb_item("huawei/vrp/ssh-login/port");
model = get_kb_item("huawei/vrp/ssh-login/" + port + "/model");

cmd = "display current-configuration";
title = "Configuring User Password Complexity Check";
solution = "Run the user-security-policy enable command to enable password complexity check.";
test_type = "SSH_Cmd";
default = "Enabled";

if(get_kb_item("Policy/vrp/installed/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No VRP device detected.";
}else if(!model || !major_version){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not determine model or version of VRP device.";
}else if(model =~ "^A[RCP]" && major_version =~ "^5"){ # nb: Test doesn't apply to AR/AC/AP devices on VRP V5
  # Don't report result if not applicable.
  exit(0);
}else if(get_kb_item("Policy/vrp/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to VRP device.";
}else if(get_kb_item("Policy/vrp/current_configuration/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not determine the current configuration.";
}else{
  current_configuration = get_kb_item("Policy/vrp/current_configuration");
  if(current_configuration !~ "undo\s+user-security-policy\s+enable")
    value = "Enabled";
  else
    value = "Disabled";

  compliant = policy_setting_exact_match(value:value, set_point:default);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
