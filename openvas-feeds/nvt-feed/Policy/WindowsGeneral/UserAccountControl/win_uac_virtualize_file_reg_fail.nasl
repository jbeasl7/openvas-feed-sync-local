# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109249");
  script_version("2023-08-25T16:09:51+0000");
  script_tag(name:"last_modification", value:"2023-08-25 16:09:51 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-06-12 15:04:04 +0200 (Tue, 12 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: User Account Control: Virtualize file and registry write failures to per-user locations");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"1;0", id:1);

  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 22H2) Benchmark v2.0.0: 2.3.17.8 (L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 2.3.17.8 (L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 2.3.17.8 (L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 5.1 Establish Secure Configurations");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations");

  script_tag(name:"summary", value:"This policy setting enables or disables the redirection of the
write failures of earlier applications to defined locations in the registry and the file system.
This feature mitigates applications that historically ran as administrator and wrote runtime
application data to %ProgramFiles%, %Windir%, %Windir%\system32, or HKEY_LOCAL_MACHINE\Software\.

This feature can be disabled for applications on devices running at least Windows Vista because it
is unnecessary.

(C) Microsoft Corporation 2015.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("version_func.inc");

target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "User Account Control: Virtualize file and registry write failures to per-user locations";
solution = "Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Local Policies/Security Options/" + title;
test_type = "RegKey";
type = "HKLM";
key = "Software\Microsoft\Windows\CurrentVersion\Policies\System";
item = "EnableVirtualization";
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