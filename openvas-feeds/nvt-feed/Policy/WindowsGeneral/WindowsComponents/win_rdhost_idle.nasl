# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109472");
  script_version("2023-08-25T05:06:04+0000");
  script_tag(name:"last_modification", value:"2023-08-25 05:06:04 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-06-27 12:56:52 +0200 (Wed, 27 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: Idle time limit (Remote Desktop Services)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Maximum", type:"entry", value:"900000", id:1);

  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 22H2) Benchmark v2.0.0: 18.10.57.3.10.1 (L2) Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less but not Never (0)'");

  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"This policy setting allows you to specify the maximum amount of
time that an active Remote Desktop Services session can be idle (without user input) before it is
automatically disconnected.

If you enable this policy setting, you must select the desired time limit in the Idle session limit
list. Remote Desktop Services will automatically disconnect active but idle sessions after the
specified amount of time. The user receives a warning two minutes before the session disconnects,
which allows the user to press a key or move the mouse to keep the session active. If you have a
console session, idle session time limits do not apply.

If you disable or do not configure this policy setting, the time limit is not specified at the Group
Policy level. By default,

Remote Desktop Services allows sessions to remain active but idle for an unlimited amount of time.

If you want Remote Desktop Services to end instead of disconnect a session when the time limit is
reached, you can configure the policy setting Computer Configuration\Administrative Templates\Windows
Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\End session when
time limits are reached.

(C) Microsoft Corporation 2015.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Set time limit for active but idle Remote Desktop Services sessions";
solution = "Set following UI path accordingly:
Windows Components/Remote Desktop Services/Remote Desktop Session Host/Session Time Limits/" + title;
type = "HKLM";
key = "Software\Policies\Microsoft\Windows NT\Terminal Services";
item = "MaxIdleTime";
reg_path = type + "\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference("Maximum");

if(!policy_verify_win_ver(min_ver:win_min_ver))
  results = policy_report_wrong_os(target_os:target_os);
else
  results = policy_min_max_reg_dword(key:key, item:item, type:type, default:default, min:FALSE,
    max:TRUE, not_zero:TRUE, as_sz:TRUE);

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:reg_path, info:comment);
policy_set_kbs(type:test_type, cmd:reg_path, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
