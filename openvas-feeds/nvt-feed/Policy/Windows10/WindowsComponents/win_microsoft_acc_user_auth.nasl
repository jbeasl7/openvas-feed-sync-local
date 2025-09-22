# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109452");
  script_version("2023-08-22T05:06:00+0000");
  script_tag(name:"last_modification", value:"2023-08-22 05:06:00 +0000 (Tue, 22 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-06-27 08:37:41 +0200 (Wed, 27 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows 10: Consumer Microsoft account user authentication");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "smb_reg_service_pack.nasl", "os_detection.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"1;0", id:1);

  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 22H2) Benchmark v2.0.0: 18.10.42.1 (L1) Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 18.9.44.1 (L1) Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 18.9.44.1 (L1) Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 16.8 Disable Any Unassociated Accounts");
  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"When enabled, this policy will prevent all applications and
services on the device from new consumer Microsoft account authentication via the Windows OnlineID
and WebAccountManager APIs. This policy may not affect applications which have already authenticated
until the authentication cache expires, so it is recommended to set this policy when setting up a
device to prevent any cached tokens from being present on the device. This policy does not affect
authentication performed directly by the user in browsers or in apps that use OAuth.

(C) Microsoft Corporation 2015.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

target_os = policy_microsoft_windows_target_string();
title = "Block all consumer Microsoft account user authentication";
solution = "Set following UI path accordingly:
Windows Components/Microsoft account/" + title;
type = "HKLM";
key = "Software\Policies\Microsoft\MicrosoftAccount";
item = "DisableUserAuth";
reg_path = type + "\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference("Value");

if(!policy_verify_win_ver())
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
