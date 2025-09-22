# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805094");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-2428", "CVE-2015-2429", "CVE-2015-2430");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-08-12 08:31:02 +0530 (Wed, 12 Aug 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows Privilege Elevation Vulnerabilities (3060716)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-090.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An elevation of privilege vulnerabilities
  are exists in Windows Object Manager when it,

  - Fails to properly validate and enforce impersonation levels.

  - Improperly allows certain registry interactions from within vulnerable
    sandboxed applications.

  - Improperly allows certain filesystem interactions from within vulnerable
    sandboxed applications.");

  script_tag(name:"impact", value:"Successful exploitation will allow  users
  to gain privileges via a crafted application.");

  script_tag(name:"affected", value:"- Microsoft Windows 8 x32/x64

  - Microsoft Windows Server 2012/R2

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3060716");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76227");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76231");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76233");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-090");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008r2:2, win8:1, win8x64:1,
                  win2012:1,win2012R2:1, win8_1:1, win8_1x64:1, win2008:3)  <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

exeVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Ntoskrnl.exe");
if(!exeVer){
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:exeVer, test_version:"6.0.6002.19453") ||
     version_in_range(version:exeVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23760"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:exeVer, test_version:"6.1.7601.18923") ||
     version_in_range(version:exeVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.23125"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  if(version_is_less(version:exeVer, test_version:"6.2.9200.17438") ||
     version_in_range(version:exeVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21547"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Win 8.1 and win2012R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:exeVer, test_version:"6.3.9600.17933"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
