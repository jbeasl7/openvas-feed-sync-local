# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109486");
  script_version("2023-08-23T05:05:12+0000");
  script_tag(name:"last_modification", value:"2023-08-23 05:05:12 +0000 (Wed, 23 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-06-27 15:29:37 +0200 (Wed, 27 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: Windows Defender SmartScreen (Explorer)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"Block;Warn", id:1);

  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 22H2) Benchmark v2.0.0: 18.10.76.2.1 (L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 18.9.80.1.1 (L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 18.9.80.1.1 (L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 2.6 Address unapproved software");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 2.7 Utilize Application Whitelisting");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 7.2 Disable Unnecessary or Unauthorized Browser or Email Client Plugins");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 7.3 Limit Use of Scripting Languages in Web Browsers and Email Clients");
  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"This policy allows you to turn Windows Defender SmartScreen on
or off.

SmartScreen helps protect PCs by warning users before running potentially malicious programs
downloaded from the Internet.

This warning is presented as an interstitial dialog shown before running an app that has been
downloaded from the Internet and is unrecognized or known to be malicious.

No dialog is shown for apps that do not appear to be suspicious.

Some information is sent to Microsoft about files and programs run on PCs with this feature enabled.

If you enable this policy, SmartScreen will be turned on for all users.

Its behavior can be controlled by the following options:

  - Warn and prevent bypass

  - Warn

If you enable this policy with the 'Warn and prevent bypass' option, SmartScreen's dialogs will not
present the user with the option to disregard the warning and run the app.

SmartScreen will continue to show the warning on subsequent attempts to run the app.

If you enable this policy with the 'Warn' option, SmartScreen's dialogs will warn the user that the
app appears suspicious, but will permit the user to disregard the warning and run the app anyway.

SmartScreen will not warn the user again for that app if the user tells SmartScreen to run the app.

If you disable this policy, SmartScreen will be turned off for all users.

Users will not be warned if they try to run suspicious apps from the Internet.

If you do not configure this policy, SmartScreen will be enabled by default, but users may change
their settings.

(C) Microsoft Corporation 2015.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Configure Windows Defender SmartScreen";
solution = "Set following UI path accordingly:
Windows Components/File Explorer/" + title;
type = "HKLM";
key = "Software\Policies\Microsoft\Windows\System";
item = "ShellSmartScreenLevel";
reg_path = type + "\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference("Value", id:1);

if(!policy_verify_win_ver(min_ver:win_min_ver))
  results = policy_report_wrong_os(target_os:target_os);
else
  results = policy_match_reg_sz(key:key, item:item, type:type, default:default, partial:FALSE);

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:reg_path, info:comment);
policy_set_kbs(type:test_type, cmd:reg_path, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
