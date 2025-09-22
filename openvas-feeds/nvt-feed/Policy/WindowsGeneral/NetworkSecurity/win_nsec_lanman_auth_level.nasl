# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109234");
  script_version("2023-08-22T05:06:00+0000");
  script_tag(name:"last_modification", value:"2023-08-22 05:06:00 +0000 (Tue, 22 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-06-12 12:20:08 +0200 (Tue, 12 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: Network security: LAN Manager authentication level");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"5;0;1;2;3;4", id:1);

  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 22H2) Benchmark v2.0.0: 2.3.11.7 (L1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 2.3.11.7 (L1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 2.3.11.7 (L1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 16.2 Configure Centralized Point of Authentication");
  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"This security setting determines which challenge/response
authentication protocol is used for network logons. This choice affects the level of authentication
protocol used by clients, the level of session security negotiated, and the level of authentication
accepted by servers as follows:

  - Send LM & NTLM responses: Clients use LM and NTLM authentication and never use NTLMv2 session
security, domain controllers accept LM, NTLM, and NTLMv2 authentication.

  - Send LM & NTLM - use NTLMv2 session security if negotiated: Clients use LM and NTLM authentication
and use NTLMv2 session security if the server supports it, domain controllers accept LM, NTLM, and
NTLMv2 authentication.

  - Send NTLM response only: Clients use NTLM authentication only and use NTLMv2 session security if
the server supports it, domain controllers accept LM, NTLM, and NTLMv2 authentication.

  - Send NTLMv2 response only: Clients use NTLMv2 authentication only and use NTLMv2 session security
if the server supports it, domain controllers accept LM, NTLM, and NTLMv2 authentication.

  - Send NTLMv2 response only\\refuse LM: Clients use NTLMv2 authentication only and use NTLMv2
session security if the server supports it, domain controllers refuse LM (accept only NTLM and
NTLMv2 authentication).

  - Send NTLMv2 response only\\refuse LM & NTLM: Clients use NTLMv2 authentication only and use
NTLMv2 session security if the server supports it, domain controllers refuse LM and NTLM (accept
only NTLMv2 authentication).

(C) Microsoft Corporation 2015.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Network security: LAN Manager authentication level";
solution = "Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Local Policies/Security Options/" + title;
type = "HKLM";
key = "System\CurrentControlSet\Control\Lsa";
item = "LmCompatibilityLevel";
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
