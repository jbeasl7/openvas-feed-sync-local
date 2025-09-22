# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901193");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-03-09 15:35:07 +0100 (Wed, 09 Mar 2011)");
  script_cve_id("CVE-2011-0032", "CVE-2011-0042");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Media Remote Code Execution Vulnerabilities (2510030)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2479943");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46680");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46682");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0615");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-015");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code
  in the context of the user running the application.");
  script_tag(name:"affected", value:"- Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Media Center Edition 2005 Service Pack 3");
  script_tag(name:"insight", value:"The flaws are caused by,

  - An error in the way DirectShow loads external libraries, which could allow
    attackers to load a malicious DLL by tricking a user into opening a file
    from a malicious location.

  - A memory corruption error in Windows Media Player and Windows Media Center
    when parsing '.dvr-ms' media files, which could allow attackers to execute
    arbitrary code by tricking a user into opening a malicious '.dvr-ms' file.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-015.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, winVista:3, win7:2) <= 0){
  exit(0);
}

## MS11-015 Hotfix
if((hotfix_missing(name:"2502898") == 0) || (hotfix_missing(name:"2479943") == 0) ||
   (hotfix_missing(name:"2494132") == 0)){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"\system32\Sbe.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.5.2600.6076")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.6.1000.18309")) {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }

    else if(version_in_range(version:dllVer, test_version:"6.6.6001.18000", test_version2:"6.6.6001.18570") ||
       version_in_range(version:dllVer, test_version:"6.6.6001.22000", test_version2:"6.6.6001.22821")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    ## Vista SP2 is showing the version 6.6.6001.18000 before applying the patch
    if(version_in_range(version:dllVer, test_version:"6.6.6001.18000", test_version2:"6.6.6002.18362") ||
       version_in_range(version:dllVer, test_version:"6.6.6002.22000", test_version2:"6.6.6002.22557")){
       security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:2) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.6.7600.16724")||
     version_in_range(version:dllVer, test_version:"6.6.7600.20000", test_version2:"6.6.7600.20864")||
     version_in_range(version:dllVer, test_version:"6.6.7601.17000", test_version2:"6.6.7601.17527")||
     version_in_range(version:dllVer, test_version:"6.6.7601.21000", test_version2:"6.6.7601.21625")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
