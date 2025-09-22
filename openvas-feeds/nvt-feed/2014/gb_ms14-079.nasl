# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804878");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2014-6317");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-11-12 07:22:06 +0530 (Wed, 12 Nov 2014)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Microsoft Windows Kernel-Mode Driver TrueType Font DoS Vulnerability (3002885)");

  script_tag(name:"summary", value:"This host is missing a moderate security
  update according to Microsoft Bulletin MS14-079.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an integer underflow error
  in the 'vFill_IFIMETRICS' function within the win32k.sys module when processing
  font files.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct denial-of-service attack.");

  script_tag(name:"affected", value:"- Microsoft Windows 2003 x32/x64 Service Pack 2 and prior

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior

  - Microsoft Windows 8 x32/x64

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012/R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3002885");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70949");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS14-079");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2, win7x64:2,
                   win2008:3, win2008r2:2, win8:1, win8x64:1, win2012:1,
                   win2012R2:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

win32SysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\win32k.sys");
if(!win32SysVer){
  exit(0);
}

if(hotfix_check_sp(win2003x64:3,win2003:3) > 0)
{
  if(version_is_less(version:win32SysVer, test_version:"5.2.3790.5448")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:win32SysVer, test_version:"6.0.6002.19215")||
     version_in_range(version:win32SysVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23521")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
   if(version_is_less(version:win32SysVer, test_version:"6.1.7601.18618")||
      version_in_range(version:win32SysVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22824")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  if(version_is_less(version:win32SysVer, test_version:"6.2.9200.17133")||
     version_in_range(version:win32SysVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21249")){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Win 8.1 and win2012R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:win32SysVer, test_version:"6.3.9600.17393")){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
