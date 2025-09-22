# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109546");
  script_version("2023-12-22T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-12-22 05:05:24 +0000 (Fri, 22 Dec 2023)");
  script_tag(name:"creation_date", value:"2018-08-07 14:04:55 +0200 (Tue, 07 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name("Microsoft Windows: Turn on MSDT interactive communication with support provider");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"0;1", id:1);

  script_xref(name:"Policy", value:"CIS Microsoft Windows 11 Enterprise Benchmark v2.0.0: 18.9.46.5.1 (L2) Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 22H2) Benchmark v2.0.0: 18.9.46.5.1 (L2) Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'");
  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"This policy setting configures Microsoft Support Diagnostic Tool
(MSDT) interactive communication with the support provider. MSDT gathers diagnostic data for
analysis by support professionals.

If you enable this policy setting, users can use MSDT to collect and send diagnostic data to a
support professional to resolve a problem.

By default, the support provider is set to Microsoft Corporation.

If you disable this policy setting, MSDT cannot run in support mode, and no data can be collected or
sent to the support provider.

If you do not configure this policy setting, MSDT support mode is enabled by default.

No reboots or service restarts are required for this policy setting to take effect. Changes take
effect immediately.

(C) 2015 Microsoft Corporation.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("version_func.inc");

target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider";
solution = "Set following UI path accordingly:
Computer Configuration/Administrative Templates/System/Troubleshooting and Diagnostics/Microsoft Support Diagnostic Tool/" + title;
test_type = "RegKey";
type = "HKLM";
key = "SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy";
item = "DisableQueryRemoteServer";
reg_path = type + "\" + key + "!" + item;
default = script_get_preference("Value");

if(!policy_verify_win_ver(min_ver:win_min_ver)){
  results = policy_report_wrong_os(target_os:target_os);
}else{
  results = policy_match_exact_reg_dword(key:key, item:item, type:type, default:default);
}

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:reg_path, info:comment);
policy_set_kbs(type:test_type, cmd:reg_path, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);