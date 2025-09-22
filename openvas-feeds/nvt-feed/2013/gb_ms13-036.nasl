# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903202");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2013-1283", "CVE-2013-1291", "CVE-2013-1292", "CVE-2013-1293");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-04-10 09:30:54 +0530 (Wed, 10 Apr 2013)");
  script_name("Microsoft Windows Kernel-Mode Drivers Privilege Elevation Vulnerabilities (2829996)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2808735");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58853");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58858");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58859");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58860");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028402");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-036");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain escalated
  privileges.");
  script_tag(name:"affected", value:"- Microsoft Windows 8

  - Microsoft Windows Server 2012

  - Microsoft Windows XP x32 Edition Service Pack 3 and prior

  - Microsoft Windows XP x64 Edition Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Improper handling of certain objects in kernel memory.

  - Improper parsing of crafted OpenType font files.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-036.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
   win7x64:2, win2008:3, win2008r2:2, win8:1, win2012:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

Win32sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Win32k.sys");
ntfsVer = fetch_file_version(sysPath:sysPath, file_name:"system32\drivers\Ntfs.sys");
if(!Win32sysVer && !ntfsVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0 && Win32sysVer)
{
  if(version_is_less(version:Win32sysVer, test_version:"5.1.2600.6364")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0 && Win32sysVer)
{
  if(version_is_less(version:Win32sysVer, test_version:"5.2.3790.5134")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(Win32sysVer)
  {
    if(version_is_less(version:Win32sysVer, test_version:"6.0.6002.18800") ||
       version_in_range(version:Win32sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23070")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }

  if(ntfsVer)
  {
   if(version_is_less(version:ntfsVer, test_version:"6.0.6002.18799") ||
      version_in_range(version:ntfsVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23069")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(Win32sysVer)
  {
    if(version_is_less(version:Win32sysVer, test_version:"6.1.7600.17266") ||
       version_in_range(version:Win32sysVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21481")||
       version_in_range(version:Win32sysVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.18104")||
       version_in_range(version:Win32sysVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.22270")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  if(ntfsVer)
  {
    if(version_is_less(version:ntfsVer, test_version:"6.1.7600.17281") ||
       version_in_range(version:ntfsVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21498")||
       version_in_range(version:ntfsVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.18126")||
       version_in_range(version:ntfsVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.22296")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  exit(0);
}

else if(hotfix_check_sp(win8:1, win2012:1) > 0 && Win32sysVer)
{
  if(version_is_less(version:Win32sysVer, test_version:"6.2.9200.16559") ||
     version_in_range(version:Win32sysVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20662")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
