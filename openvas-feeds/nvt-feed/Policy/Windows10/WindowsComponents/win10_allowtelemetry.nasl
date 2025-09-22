# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109094");
  script_version("2023-12-22T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-12-22 05:05:24 +0000 (Fri, 22 Dec 2023)");
  script_tag(name:"creation_date", value:"2018-04-23 12:03:04 +0200 (Mon, 23 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows 10: Allow Telemetry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "smb_reg_service_pack.nasl", "os_detection.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"0;1;2;3", id:1);

  script_xref(name:"Policy", value:"CIS Microsoft Windows 11 Enterprise Benchmark v2.0.0: 18.10.15.1 (L1) Ensure 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 22H2) Benchmark v2.0.0: 18.10.15.1 (L1) Ensure 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 18.9.16.1 (L1) Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]' or 'Enabled: 1 - Basic'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 18.9.16.1 (L1) Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]' or 'Enabled: 1 - Basic'");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 13.3 Monitor and Block Unauthorized Network Traffic");
  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"This policy setting determines the amount of Windows diagnostic
data sent to Microsoft.

A value of 0 (Security) will send minimal data to Microsoft to keep Windows secure. Windows security
components such as Malicious Software Removal Tool (MSRT) and Windows Defender may send data to
Microsoft at this level if they are enabled. Setting a value of 0 applies to Enterprise, EDU, IoT
and Server devices only. Setting a value of 0 for other devices is equivalent to setting a value of 1.

A value of 1 (Basic) sends the same data as a value of 0, plus a very limited amount of diagnostic
data such as basic device info, quality-related data, and app compatibility info. Note that setting
values of 0 or 1 will degrade certain experiences on the device.

A value of 2 (Enhanced) sends the same data as a value of 1, plus additional data such as how
Windows, Windows Server, System Center, and apps are used, how they perform, and advanced
reliability data.

A value of 3 (Full) sends the same data as a value of 2, plus advanced diagnostics data used to
diagnose and fix problems with devices, which can include the files and content that may have caused
a problem with the device.

Windows 10 diagnostics data settings applies to the Windows operating system and apps included with
Windows. This setting does not apply to third party apps running on Windows 10.

If you disable or do not configure this policy setting, users can configure the Telemetry level in
Settings.

Note: Recommended setting is Enabled: 0 - Security [Enterprise Only] or
Enabled: 1 - Basic

(C) Microsoft Corporation 2015.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("version_func.inc");
include("host_details.inc");

target_os = policy_microsoft_windows_target_string();
title = "Allow Telemetry";
solution = "Set following UI path accordingly:
Computer Configuration/Administrative Templates/Windows Components/
Data Collection and Preview Builds/" + title;
test_type = "RegKey";
type = "HKLM";
key = "SOFTWARE\Policies\Microsoft\Windows\DataCollection";
item = "AllowTelemetry";
reg_path = type + "\" + key + "!" + item;
default = script_get_preference("Value", id:1);

if(!policy_verify_win_ver())
  results = policy_report_wrong_os(target_os:target_os);
else
  results = policy_match_exact_reg_dword(key:key, item:item, type:type, default:default);

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

if(value == 0 || value == 1){
  compliant = "yes";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:reg_path, info:comment);
policy_set_kbs(type:test_type, cmd:reg_path, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);