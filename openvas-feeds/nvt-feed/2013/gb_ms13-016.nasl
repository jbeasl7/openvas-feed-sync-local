# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902943");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2013-1248", "CVE-2013-1249", "CVE-2013-1250", "CVE-2013-1264",
                "CVE-2013-1251", "CVE-2013-1265", "CVE-2013-1252", "CVE-2013-1266",
                "CVE-2013-1253", "CVE-2013-1267", "CVE-2013-1254", "CVE-2013-1255",
                "CVE-2013-1256", "CVE-2013-1257", "CVE-2013-1258", "CVE-2013-1259",
                "CVE-2013-1260", "CVE-2013-1261", "CVE-2013-1262", "CVE-2013-1263",
                "CVE-2013-1268", "CVE-2013-1269", "CVE-2013-1270", "CVE-2013-1271",
                "CVE-2013-1272", "CVE-2013-1273", "CVE-2013-1274", "CVE-2013-1275",
                "CVE-2013-1276", "CVE-2013-1277");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-02-13 06:40:06 +0530 (Wed, 13 Feb 2013)");
  script_name("Microsoft Windows Kernel-Mode Drivers Privilege Elevation Vulnerabilities (2778344)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2778344");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57786");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57791");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57792");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57793");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57794");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57795");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57796");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57797");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57798");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57799");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57800");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57801");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57802");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57803");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57804");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57805");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57806");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57807");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57808");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57809");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57810");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57811");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57812");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57813");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57814");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57815");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57816");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57817");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57818");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57819");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028124");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-016");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to a specially crafted
  program to exploit race conditions in 'win32k.sys' and gain System level
  privileges.");
  script_tag(name:"affected", value:"- Microsoft Windows XP x32 Edition Service Pack 3 and prior

  - Microsoft Windows XP x64 Edition Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");
  script_tag(name:"insight", value:"The flaws due to an error in 'win32k.sys' when handling kernel-mode driver
  objects in memory.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-016.");
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

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Win32k.sys");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  if(version_is_less(version:sysVer, test_version:"5.1.2600.6334")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
{
  if(version_is_less(version:sysVer, test_version:"5.2.3790.5106")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.0.6002.18764") ||
     version_in_range(version:sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23012")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.1.7600.17206") ||
     version_in_range(version:sysVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21415")||
     version_in_range(version:sysVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.18042")||
     version_in_range(version:sysVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.22208")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
