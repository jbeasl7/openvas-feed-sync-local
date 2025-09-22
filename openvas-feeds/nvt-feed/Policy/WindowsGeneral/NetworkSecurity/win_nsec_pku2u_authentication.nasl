# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109231");
  script_version("2023-08-22T05:06:00+0000");
  script_tag(name:"last_modification", value:"2023-08-22 05:06:00 +0000 (Tue, 22 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-06-12 10:28:28 +0200 (Tue, 12 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: Network security: Allow PKU2U authentication requests to this computer to use online identities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"0;1", id:1);

  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 22H2) Benchmark v2.0.0: 2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 16.2 Configure Centralized Point of Authentication");
  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"Starting with Windows Server 2008 R2 and Windows 7, the
Negotiate Security Support Provider (SSP) supports an extension SSP, Negoexts.dll. This extension
SSP is treated as an authentication protocol by the Windows operating system, and it supports SSPs
from Microsoft, including PKU2U. You can also develop or add other SSPs.

When devices are configured to accept authentication requests by using online IDs, Negoexts.dll
calls the PKU2U SSP on the computer that is used to log on. The PKU2U SSP obtains a local
certificate and exchanges the policy between the peer computers. When validated on the peer computer,
the certificate within the metadata is sent to the logon peer for validation. It associates the
user's certificate to a security token, and then the logon process completes.

(C) Microsoft Corporation 2015.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Network security: Allow PKU2U authentication requests to this computer to use online identities";
solution = "Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Local Policies/Security Options/" + title;
type = "HKLM";
key = "System\CurrentControlSet\Control\Lsa\pku2u";
item = "AllowOnlineID";
reg_path = type + "\" + key + "!" + item;
test_type = "RegKey";
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
