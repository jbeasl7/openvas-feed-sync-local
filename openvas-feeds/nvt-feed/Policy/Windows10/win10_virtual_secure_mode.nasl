# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.115070");
  script_version("2023-12-01T16:11:30+0000");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-01 10:32:08 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: Virtual Secure Mode");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_xref(name:"Policy", value:"SYS.2.2.3.A26 Use of Virtual Secure Mode (VSM) (H)");
  script_xref(name:"URL", value:"https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Cyber-Sicherheit/SiSyPHus/E20172000_BSI_Win10_VSMABGL_Win10_v_1_0.pdf?__blob=publicationFile&v=4");

  script_tag(name:"summary", value:"When using Virtual Secure Mode (VSM) SHOULD It should be taken
  into account that forensic investigations, e.g. B. for security incident handling be restricted
  or made more difficult.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

target_os = "Microsoft Windows 10 or higher";
win_min_ver = "6.3";
title = "Use of Virtual Secure Mode (VSM)";
solution = "When using Virtual Secure Mode (VSM), it SHOULD be taken into account that forensic investigations, e.g. B. for security incident handling, restricted or made more difficult.
To resolve this, turn on Virtual Secure Mode via Group Policy or per your organization's policies.";
test_type = "Powershell";
type = "HKLM";
key = "SOFTWARE\Policies\Microsoft\Windows\DeviceGuard";
item = "EnableVirtualizationBasedSecurity";
reg_patch = type + "\" + key + "!" + item;
default = "1";
comment = "";


if(!policy_verify_win_ver(min_ver:win_min_ver))
  results = policy_report_wrong_os(target_os:target_os);
else
  results = policy_match_exact_reg_dword(key:key, item:item, type:type, default:default);

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test_type:reg_patch, info:comment);
policy_set_kbs(type:test_type, cmd:reg_patch, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit( 0 );