# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809308");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-3302");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-16 16:23:00 +0000 (Thu, 16 May 2019)");
  script_tag(name:"creation_date", value:"2016-09-14 07:48:12 +0530 (Wed, 14 Sep 2016)");
  script_name("Microsoft Windows Lock Screen Elevation of Privilege Vulnerability (3178469)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-112.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to when windows improperly
  allows web content to load from the Windows lock screen.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute code on a user's locked computer.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 x32/x64

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows Server 2012R2

  - Microsoft Windows 10 Version 1511 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3178469");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92853");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-112");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(hotfix_check_sp(win2012R2:1, win8_1:1, win8_1x64:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

PniVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Pnidui.dll");
if(!PniVer){
  exit(0);
}


## Win 8.1 and win2012R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:PniVer, test_version:"6.3.9600.18434"))
  {
    Vulnerable_range = "Less than 6.3.9600.18434";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:PniVer, test_version:"10.0.10240.17113"))
  {
    Vulnerable_range = "Less than 10.0.10240.17113";
    VULN = TRUE;
  }

  else if(version_in_range(version:PniVer, test_version:"10.0.10586.0", test_version2:"10.0.10586.588"))
  {
    Vulnerable_range = "10.0.10586.0 - 10.0.10586.588";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\System32\Pnidui.dll" + '\n' +
           'File version:     ' + PniVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
