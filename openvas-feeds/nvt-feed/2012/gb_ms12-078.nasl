# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902936");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-2556", "CVE-2012-4786");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-12-12 09:08:07 +0530 (Wed, 12 Dec 2012)");
  script_name("Microsoft Windows Kernel-Mode Drivers Remote Code Execution Vulnerabilities (2783534)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2753842");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56841");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56842");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2779030");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-078");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_smb_windows_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code with kernel-mode privileges.");
  script_tag(name:"affected", value:"- Microsoft Windows XP x32 Edition Service Pack 3 and prior

  - Microsoft Windows XP x64 Edition Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");
  script_tag(name:"insight", value:"- An error in the OpenType Font (OTF) driver when handling certain objects
    can be exploited via a specially crafted font file.

  - An error when handling certain TrueType Fonts (TTF) can be exploited
    via a specially crafted font file.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-078.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
                   win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

winsVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Win32k.sys");
afdVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Atmfd.dll");

if(winsVer || afdVer)
{
  if(hotfix_check_sp(xp:4) > 0)
  {
    if(version_is_less(version:winsVer, test_version:"5.1.2600.6322") ||
       version_is_less(version:afdVer, test_version:"5.1.2.235")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
  {

    if(version_is_less(version:winsVer, test_version:"5.2.3790.5094") ||
       version_is_less(version:afdVer, test_version:"5.2.2.235")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  ## Currently not supporting for Vista and Windows Server 2008 64 bit
  else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    if(version_is_less(version:winsVer, test_version:"6.0.6002.18733") ||
       version_in_range(version:winsVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22976") ||
       version_is_less(version:afdVer, test_version:"5.1.2.235")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
  {
    if(version_is_less(version:winsVer, test_version:"6.1.7600.17174") ||
       version_in_range(version:winsVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21378")||
       version_in_range(version:winsVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.18008")||
       version_in_range(version:winsVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.22170") ||
       version_is_less(version:afdVer, test_version:"5.1.2.237")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
