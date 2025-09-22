# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109519");
  script_version("2023-08-22T05:06:00+0000");
  script_tag(name:"last_modification", value:"2023-08-22 05:06:00 +0000 (Tue, 22 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-06-28 16:22:17 +0200 (Thu, 28 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: Notify antivirus programs when opening attachments");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"3;1", id:1);

  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 22H2) Benchmark v2.0.0: 19.7.4.2 (L1) Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 19.7.4.2 (L1) Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 19.7.4.2 (L1) Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 7.9 Block Unnecessary File Types");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 7.10 Sandbox All Email Attachments");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 8.1 Utilize Centrally Managed Anti-malware Software");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 8.2 Ensure Anti-Malware Software and Signatures are Updated");
  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"This policy setting allows you to manage the behavior for
notifying registered antivirus programs. If multiple programs are registered, they will all be
notified. If the registered antivirus program already performs on-access checks or scans files as
they arrive on the computer's email server, additional calls would be redundant.

If you enable this policy setting, Windows tells the registered antivirus program to scan the file
when a user opens a file attachment. If the antivirus program fails, the attachment is blocked from
being opened.

If you disable this policy setting, Windows does not call the registered antivirus programs when
file attachments are opened.

If you do not configure this policy setting, Windows does not call the registered antivirus programs
when file attachments are opened.

(C) Microsoft Corporation 2015.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Notify antivirus programs when opening attachments";
solution = "Set following UI path accordingly:
User Configuration/Administrative Templates/Windows Components/Attachment Manager/" + title;
type = "HKU";
item = "ScanWithAntiVirus";
key = "Software\Microsoft\Windows\CurrentVersion\Policies\Attachments";
reg_path = type + "\[SID]\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference("Value");

if(!policy_verify_win_ver(min_ver:win_min_ver))
  results = policy_report_wrong_os(target_os:target_os);
else if(!sids = registry_hku_subkeys())
  results = policy_report_empty_hku();
else
  results = policy_match_exact_dword_profiles(key:key, item:item, default:default, sids:sids);

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:reg_path, info:comment);
policy_set_kbs(type:test_type, cmd:reg_path, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);