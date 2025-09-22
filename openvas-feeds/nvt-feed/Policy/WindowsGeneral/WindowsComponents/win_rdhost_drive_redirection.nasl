# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109466");
  script_version("2023-08-25T05:06:04+0000");
  script_tag(name:"last_modification", value:"2023-08-25 05:06:04 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-06-27 11:28:42 +0200 (Wed, 27 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: Do not allow drive redirection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"1;0", id:1);

  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 22H2) Benchmark v2.0.0: 18.10.57.3.3.3 (L1) Ensure 'Do not allow drive redirection' is set to 'Enabled'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 18.9.62.3.3.2 (L1) Ensure 'Do not allow drive redirection' is set to 'Enabled'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 18.9.59.3.3.2 (L1) Ensure 'Do not allow drive redirection' is set to 'Enabled'");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 14.6 Protect Information through Access Control Lists");
  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"This policy setting specifies whether to prevent the mapping of
client drives in a Remote Desktop Services session (drive redirection).

By default, an RD Session Host server maps client drives automatically upon connection. Mapped
drives appear in the session folder tree in File Explorer or Computer in the format <driveletter> on
<computername>. You can use this policy setting to override this behavior.

If you enable this policy setting, client drive redirection is not allowed in Remote Desktop
Services sessions, and Clipboard file copy redirection is not allowed on computers running Windows
Server 2003, Windows 8, and Windows XP.

If you disable this policy setting, client drive redirection is always allowed. In addition,
Clipboard file copy redirection is always allowed if Clipboard redirection is allowed.

If you do not configure this policy setting, client drive redirection and Clipboard file copy
redirection are not specified at the Group Policy level.

(C) Microsoft Corporation 2015.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("version_func.inc");

target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Do not allow drive redirection";
solution = "Set following UI path accordingly:
Computer Configuration/Administrative Templates/Windows Components/
Remote Desktop Services/Remote Desktop Session Host/Device and Resource Redirection/" + title;
test_type = "RegKey";
type = "HKLM";
key = "Software\Policies\Microsoft\Windows NT\Terminal Services";
item = "fDisableCdm";
reg_path = type + "\" + key + "!" + item;
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