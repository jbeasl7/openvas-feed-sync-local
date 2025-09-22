# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109339");
  script_version("2023-08-23T05:05:12+0000");
  script_tag(name:"last_modification", value:"2023-08-23 05:05:12 +0000 (Wed, 23 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-06-22 14:49:11 +0200 (Fri, 22 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows 10: Automatically connect to suggested open hotspots");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "smb_reg_service_pack.nasl", "os_detection.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"0;1", id:1);

  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 22H2) Benchmark v2.0.0: 18.6.23.2.1 (L1) Ensure 'Allow Windows to automatically connect to suggested open hotspots to networks shared by contacts and to hotspots offering paid services' is set to 'Disabled'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 18.5.23.2.1  (L1) Ensure 'Allow Windows to automatically connect to suggested open hotspots networks shared by contacts and to hotspots offering paid services' is set to 'Disabled'");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 15.4 Disable Wireless Access on Devices if Not Required");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 15.5 Limit Wireless Access on Client Devices");

  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"This policy setting determines whether users can enable the
following WLAN settings:'Connect to suggested open hotspots, 'Connect to networks shared by my
contacts', and 'Enable paid services'.

'Connect to suggested open hotspots' enables Windows to automatically connect users to open hotspots
it knows about by crowdsourcing networks that other people using Windows have connected to.

'Connect to networks shared by my contacts' enables Windows to automatically connect to networks
that the user's contacts have shared with them, and enables users on this device to share networks
with their contacts.

'Enable paid services' enables Windows to temporarily connect to open hotspots to determine if paid
services are available.

If this policy setting is disabled, both 'Connect to suggested open hotspots', 'Connect to networks
shared by my contacts' and 'Enable paid services' will be turned off and users on this device will
be prevented from enabling them.

If this policy setting is not configured or is enabled, users can choose to enable or disable either
'Connect to suggested open hotspots' or 'Connect to networks shared by my contacts'.

(C) Microsoft Corporation 2015.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("version_func.inc");
include("host_details.inc");

target_os = policy_microsoft_windows_target_string();
title = "Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services";
solution = "Set following UI path accordingly:
Computer Configuration/Administrative Templates/Network/WLAN Service/WLAN Settings/" + title;
test_type = "RegKey";
type = "HKLM";
key = "Software\Microsoft\wcmsvc\wifinetworkmanager\config";
item = "AutoConnectAllowedOEM";
reg_path = type + "\" + key + "!" + item;
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