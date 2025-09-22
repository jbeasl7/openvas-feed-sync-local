# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109232");
  script_version("2023-08-22T05:06:00+0000");
  script_tag(name:"last_modification", value:"2023-08-22 05:06:00 +0000 (Tue, 22 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-06-12 10:28:28 +0200 (Tue, 12 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: Network security: Encryption types allowed for Kerberos");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"DES-CBC-CRC", type:"radio", value:"Disabled;Enabled", id:1);
  script_add_preference(name:"DES-CBC-MD5", type:"radio", value:"Disabled;Enabled", id:2);
  script_add_preference(name:"RC4-HMAC", type:"radio", value:"Disabled;Enabled", id:3);
  script_add_preference(name:"AES128-CTS-HMAC-SHA1-96", type:"radio", value:"Enabled;Disabled", id:4);
  script_add_preference(name:"AES256-CTS-HMAC-SHA1-96", type:"radio", value:"Enabled;Disabled", id:5);
  script_add_preference(name:"Future encryption types", type:"radio", value:"Enabled;Disabled", id:6);

  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 22H2) Benchmark v2.0.0: 2.3.11.4 (L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1' 'AES256_HMAC_SHA1' and 'Future encryption types'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 2.3.11.4 (L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1' 'AES256_HMAC_SHA1' and 'Future encryption types'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 2.3.11.4 (L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1' 'AES256_HMAC_SHA1' and 'Future encryption types'");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 16.4 Encrypt or Hash all Authentication Credentials");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 16.5 Ensure Workstation Screen Locks Are Configured");
  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"This policy setting allows you to set the encryption types that
Kerberos is allowed to use.

If not selected, the encryption type will not be allowed. This setting may affect compatibility with
client computers or services and applications. Multiple selections are permitted.

(C) Microsoft Corporation 2015.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");
include("byte_func.inc");

FutureEncryptionTypes = script_get_preference('Future encryption types');
AES256 = script_get_preference('AES256-CTS-HMAC-SHA1-96');
AES128 = script_get_preference('AES128-CTS-HMAC-SHA1-96');
RC4HMAC = script_get_preference('RC4-HMAC');
MD5 = script_get_preference('DES-CBC-MD5');
CRC = script_get_preference('DES-CBC-CRC');

if(FutureEncryptionTypes == 'Enabled'){
  default += ',Future encryption types';
  bin = '11111111111111111111111111';
}else{
  bin = '0';
}
if(AES256 == 'Enabled'){
  default += ',AES256-CTS-HMAC-SHA1-96';
  bin += '1';
}else{
  bin += '0';
}
if(AES128 == 'Enabled'){
  default += ',AES128-CTS-HMAC-SHA1-96';
  bin += '1';
}else{
  bin += '0';
}
if(RC4HMAC == 'Enabled'){
  default += ',RC4-HMAC';
  bin += '1';
}else{
  bin += '0';
}
if(MD5 == 'Enabled'){
  default += ',ADES-CBC-MD5';
  bin += '1';
}else{
  bin += '0';
}
if(CRC == 'Enabled'){
  default += ',DES-CBC-CRC';
  bin += '1';
}else{
  bin += '0';
}

def = bin2dec(bin:bin);

target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Network security: Configure encryption types allowed for Kerberos";
solution = "Set following UI path accordingly: Computer Configuration/Windows Settings/Local Policies/Security Options/" + title;
type = "HKLM";
key = "Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters";
item = "SupportedEncryptionTypes";
reg_path = type + "\" + key + "!" + item;
test_type = "RegKey";
default = str_replace(string:default, find:",", replace:"", count:1) + " (" + def + ")";

if(!policy_verify_win_ver(min_ver:win_min_ver))
  results = policy_report_wrong_os(target_os:target_os);
else
  results = policy_match_exact_reg_dword(key:key, item:item, type:type, default:def);

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:reg_path, info:comment);
policy_set_kbs(type:test_type, cmd:reg_path, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
