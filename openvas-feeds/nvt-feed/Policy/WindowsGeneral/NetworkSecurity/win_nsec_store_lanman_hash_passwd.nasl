# Copyright (C) 2018 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109233");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2018-06-12 10:46:43 +0200 (Tue, 12 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: Network security: Do not store LAN Manager hash value on next password change");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"1;0", id:1);

  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 2.3.11.5 (L1) Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 2.3.11.5 (L1) Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 16.4 Encrypt or Hash all Authentication Credentials");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 16.5 Ensure Workstation Screen Locks Are Configured");
  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"This policy setting determines whether LAN Manager is prevented
from storing hash values for the new password the next time the password is changed. Hash values are
a representation of the password after the encryption algorithm is applied that corresponds to the
format that is specified by the algorithm. To decrypt the hash value, the encryption algorithm must
be determined and then reversed. The LAN Manager hash is relatively weak and prone to attack
compared to the cryptographically stronger NTLM hash. Because the LM hash is stored on the local
device in the security database, the passwords can be compromised if the security database, Security
Accounts Manager (SAM), is attacked.

By attacking the SAM file, attackers can potentially gain access to user names and password hashes.
Attackers can use a password-cracking tool to determine what the password is. After they have access
to this information, they can use it to gain access to resources on your network by impersonating
users. Enabling this policy setting will not prevent these types of attacks, but it will make them
much more difficult.

(C) Microsoft Corporation 2015.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Network security: Do not store LAN Manager hash value on next password change";
solution = "Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Local Policies/Security Options/" + title;
type = "HKLM";
key = "System\CurrentControlSet\Control\Lsa";
item = "NoLMHash";
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
