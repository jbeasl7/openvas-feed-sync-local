# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109475");
  script_version("2023-08-25T05:06:04+0000");
  script_tag(name:"last_modification", value:"2023-08-25 05:06:04 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-06-27 13:11:06 +0200 (Wed, 27 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: Temporary folders per session (Remote Desktop Services)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"1;0", id:1);

  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 22H2) Benchmark v2.0.0: REMOVE - 18.9.58.3.11 (L1) Ensure 'Do not use temporary folders per session' is set to 'Disabled' Ticket #8788");
  script_xref(name:"Policy", value:"CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 18.9.59.3.11.2 (L1) Ensure 'Do not use temporary folders per session' is set to 'Disabled'");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 14.6 Protect Information through Access Control Lists");
  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"This policy setting allows you to prevent Remote Desktop
Services from creating session-specific temporary folders.

You can use this policy setting to disable the creation of separate temporary folders on a remote
computer for each session. By default, Remote Desktop Services creates a separate temporary folder
for each active session that a user maintains on a remote computer. These temporary folders are
created on the remote computer in a Temp folder under the user's profile folder and are named with
the sessionid.

If you enable this policy setting, per-session temporary folders are not created. Instead, a user's
temporary files for all sessions on the remote computer are stored in a common Temp folder under the
user's profile folder on the remote computer.

If you disable this policy setting, per-session temporary folders are always created, even if the
server administrator specifies otherwise.

If you do not configure this policy setting, per-session temporary folders are created unless the
server administrator specifies otherwise.

(C) Microsoft Corporation 2015.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Do not use temporary folders per session";
solution = "Set following UI path accordingly:
Windows Components/Remote Desktop Services/Remote Desktop Session Host/Temporary folders/" + title;
type = "HKLM";
key = "Software\Policies\Microsoft\Windows NT\Terminal Services";
item = "PerSessionTempDir";
reg_path = type + "\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference("Value");

if(!policy_verify_win_ver(min_ver:win_min_ver))
  results = policy_report_wrong_os(target_os:target_os);
else
  results = policy_match_exact_reg_dword(key:key, item:item, type:type, default:default);

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:reg_path, info:comment);
policy_set_kbs(type:test_type, cmd:reg_path, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
