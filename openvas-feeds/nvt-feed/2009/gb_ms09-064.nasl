# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901047");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-11-11 19:07:38 +0100 (Wed, 11 Nov 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2523");
  script_name("Microsoft Windows License Logging Server Remote Code Execution Vulnerability (974783)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/974783");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36921");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3190");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-064");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to crash an affected
  Service or execute arbitrary code on the victim's system.");

  script_tag(name:"affected", value:"Microsoft Windows 2K  Service Pack 4 and prior.");

  script_tag(name:"insight", value:"This issue is caused by a buffer overflow error in 'Llssrv.exe' when handling
  specially crafted RPC packets.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-064.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5) <= 0){
  exit(0);
}

if(!registry_key_exists(key:"SYSTEM\CurrentControlSet\Services"+
                                            "\LicenseService")){
 exit(0);
}

# MS09-064 Hotfix check
if(hotfix_missing(name:"974783") == 0){
  exit(0);
}

exePath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                         item:"Install Path");
if(!exePath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
file = ereg_replace(pattern:"[A-Z]:(.*)",  replace:"\1",  string:exePath +
                                                           "\Llssrv.exe");
exeVer = GetVer(file:file, share:share);
if(!exeVer){
  exit(0);
}

if(version_is_less(version:exeVer, test_version:"5.0.2195.7337")){
  report = report_fixed_ver(installed_version:exeVer, fixed_version:"5.0.2195.7337");
  security_message(port: 0, data: report);
}
