# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902335");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-02-09 17:14:46 +0100 (Wed, 09 Feb 2011)");
  script_cve_id("CVE-2011-0033");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Vulnerability in the OpenType Compact Font Format (CFF) Driver Could Allow Remote Code Execution (2485376)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0320");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46106");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-007");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will allow the remote attackers or malicious users to
  execute arbitrary code with kernel privileges.");
  script_tag(name:"affected", value:"- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior");
  script_tag(name:"insight", value:"The flaw is caused by an error in the Windows OpenType Compact Font Format
  (CFF) driver that does not properly validate the parameter values of
  specially crafted OpenType fonts.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-007.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## MS11-007 Hotfix
if((hotfix_missing(name:"2485376") == 0)){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Atmfd.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(xp:4, winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"5.1.2.231"))
  {
    report = report_fixed_ver(installed_version:dllVer, fixed_version:"5.1.2.231", install_path:sysPath);
    security_message(port: 0, data: report);
    exit(0);
  }
}

if(hotfix_check_sp(win7:2) > 0)
{
  if(version_is_less(version:dllVer, test_version:"5.1.2.232"))
  {
    report = report_fixed_ver(installed_version:dllVer, fixed_version:"5.1.2.232", install_path:sysPath);
    security_message(port: 0, data: report);
    exit(0);
  }
}

if(hotfix_check_sp(win2003:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"5.2.2.231")){
    report = report_fixed_ver(installed_version:dllVer, fixed_version:"5.2.2.231", install_path:sysPath);
    security_message(port: 0, data: report);
  }
}
