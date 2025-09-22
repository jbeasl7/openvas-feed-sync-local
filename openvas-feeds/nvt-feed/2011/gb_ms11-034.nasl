# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900283");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-04-13 17:05:53 +0200 (Wed, 13 Apr 2011)");
  script_cve_id("CVE-2011-0662", "CVE-2011-0665", "CVE-2011-0666", "CVE-2011-0667", "CVE-2011-0670",
                "CVE-2011-0671", "CVE-2011-0672", "CVE-2011-0674", "CVE-2011-0675", "CVE-2011-1234",
                "CVE-2011-1235", "CVE-2011-1236", "CVE-2011-1237", "CVE-2011-1238", "CVE-2011-1239",
                "CVE-2011-1240", "CVE-2011-1241", "CVE-2011-1242", "CVE-2011-0673", "CVE-2011-0676",
                "CVE-2011-0677", "CVE-2011-1225", "CVE-2011-1226", "CVE-2011-1227", "CVE-2011-1228",
                "CVE-2011-1229", "CVE-2011-1230", "CVE-2011-1231", "CVE-2011-1232", "CVE-2011-1233");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Windows Kernel-Mode Drivers Privilege Elevation Vulnerabilities (2506223)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow local attackers to gain elevated
  privileges.");
  script_tag(name:"affected", value:"- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior");
  script_tag(name:"insight", value:"The flaws are due to improper Kernel-mode driver object management
  and Null pointer de-reference due to the way kernel-mode drivers keep track
  of pointers to certain kernel-mode driver objects.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-034.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2506223");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47194");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47202");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47203");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47204");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47205");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47206");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47207");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47209");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47210");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47211");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47212");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47213");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47214");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47215");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47216");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47217");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47218");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47219");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47220");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47224");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47225");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47226");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47227");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47228");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47229");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47230");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47231");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47232");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47233");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47234");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-034");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## MS11-034 Hotfix (2506223)
if(hotfix_missing(name:"2506223") == 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Win32k.sys");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"5.1.2600.6090")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"5.2.3790.4841")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 1" >< SP)
  {
    if(version_in_range(version:sysVer, test_version:"6.0.6001.18000", test_version2:"6.0.6001.18611")||
       version_in_range(version:sysVer, test_version:"6.0.6001.22000", test_version2:"6.0.6001.22866")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_in_range(version:sysVer, test_version:"6.0.6002.18000", test_version2:"6.0.6002.18416")||
       version_in_range(version:sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22600")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:2) > 0)
{
  if(version_in_range(version:sysVer, test_version:"6.1.7600.16000", test_version2:"6.1.7600.16771")||
     version_in_range(version:sysVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.20913")||
     version_in_range(version:sysVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17569")||
     version_in_range(version:sysVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21672")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
