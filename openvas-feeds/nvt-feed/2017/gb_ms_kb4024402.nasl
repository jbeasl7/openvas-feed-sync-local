# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811204");
  script_version("2025-04-07T05:39:52+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-8543", "CVE-2017-8544");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-07 05:39:52 +0000 (Mon, 07 Apr 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-04 20:28:18 +0000 (Fri, 04 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-06-14 08:32:08 +0530 (Wed, 14 Jun 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4024402)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4024402.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist because Windows Search
  improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to take control of the affected system. An attacker could then
  install programs, view, change, or delete data, or create new accounts with
  full user rights and obtain sensitive information.");

  script_tag(name:"affected", value:"- Microsoft Windows XP SP2 x64

  - Microsoft Windows XP SP3 x86

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2

  - Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4024402");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98824");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98826");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4025687");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3,
                   win2008:3, winVistax64:3, win2008x64:3) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"query.dll");
if(!fileVer){
  exit(0);
}


if(hotfix_check_sp(xp:4) > 0)
{
  if(version_is_less(version:fileVer, test_version:"5.1.2600.7273"))
  {
    Vulnerable_range = "Less than 5.1.2600.7273";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2003:3, win2003x64:3, xpx64:3) > 0)
{
  if(version_is_less(version:fileVer, test_version:"5.2.3790.6100"))
  {
    Vulnerable_range = "Less than 5.2.3790.6100";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\query.dll" + '\n' +
           'File version:     ' + fileVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
