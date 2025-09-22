# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902916");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-0217", "CVE-2012-1515");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-06-13 09:21:39 +0530 (Wed, 13 Jun 2012)");
  script_name("Microsoft Windows Kernel Privilege Elevation Vulnerabilities (2711167)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2707511");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52820");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53856");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1027155");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-042");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code with kernel-mode privileges.");
  script_tag(name:"affected", value:"- Microsoft Windows 7 x64 Edition Service Pack 1 and prior

  - Microsoft Windows XP x32 Edition Service Pack 3 and prior

  - Microsoft Windows 2K3 x32 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 x64 Edition Service Pack 1 and prior");
  script_tag(name:"insight", value:"The flaws are due to an:

  - Error in the User Mode Scheduler (UMS) when handling a particular system
    request can be exploited to execute arbitrary code.

  - Error in incorrect protection of BIOS ROM can be exploited to execute
    arbitrary code.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-042.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4 ,win2003:3, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

exeVer = fetch_file_version(sysPath:sysPath, file_name:"system32\ntoskrnl.exe");
if(!exeVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  if(version_is_less(version:exeVer, test_version:"5.1.2600.6223")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win2003:3) > 0)
{
  if(version_is_less(version:exeVer, test_version:"5.2.3790.4998")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:exeVer, test_version:"6.1.7600.17017") ||
     version_in_range(version:exeVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21206")||
     version_in_range(version:exeVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17834")||
     version_in_range(version:exeVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21986")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
