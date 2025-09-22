# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903417");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2013-3899", "CVE-2013-3902", "CVE-2013-3903", "CVE-2013-3907",
                "CVE-2013-5058");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-12-11 08:49:46 +0530 (Wed, 11 Dec 2013)");
  script_name("Microsoft Windows Kernel Local Privilege Escalation Vulnerabilities (2880430)");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-101");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error within the win32k.sys driver can be exploited to corrupt memory.

  - A use-after-free error exists within the win32k.sys driver.

  - An error when processing TrueType font files can be exploited to cause
  a crash.

  - A double fetch error exists within the portcls.sys driver.

  - An integer overflow error exists within the win32k.sys driver.");

  script_tag(name:"affected", value:"- Microsoft Windows 8

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012

  - Microsoft Windows XP x32 Service Pack 3 and prior

  - Microsoft Windows XP x64 Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows 2003 x32/x64 Service Pack 2 and prior

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a DoS (Denial of
Service) and gain escalated privileges.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2893984");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64080");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64084");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64087");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64090");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64091");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2887069");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1029461");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-101");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
                   win7x64:2, win2008:3, win2008r2:2, win8:1, win2012:1,
                   win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

win32SysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\win32k.sys");
if(!win32SysVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  if(version_is_less(version:win32SysVer, test_version:"5.1.2600.6473")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(xpx64:3,win2003x64:3,win2003:3) > 0)
{
  if(version_is_less(version:win32SysVer, test_version:"5.2.3790.5250")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:win32SysVer, test_version:"6.0.6002.18974") ||
     version_in_range(version:win32SysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23260")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:win32SysVer, test_version:"6.1.7601.18300") ||
     version_in_range(version:win32SysVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22495")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  if(version_is_less(version:win32SysVer, test_version:"6.2.9200.16758") ||
     version_in_range(version:win32SysVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20870")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Win 8.1
## Currently not supporting for Windows Server 2012 R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1) > 0)
{
  if(version_is_less(version:win32SysVer, test_version:"6.3.9600.16457")){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
