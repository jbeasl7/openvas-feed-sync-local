# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901205");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-09-14 16:05:49 +0200 (Wed, 14 Sep 2011)");
  script_cve_id("CVE-2011-1991");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Components Remote Code Execution Vulnerabilities (2570947)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2570947");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47741");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-071");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attacker to execute arbitrary
  code by enticing an unsuspecting victim to open a file on a remote SMB or
  WebDAV share.");
  script_tag(name:"affected", value:"- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior");
  script_tag(name:"insight", value:"The flaw exists when specific Windows components incorrectly restrict the
  path used for loading external libraries. An attacker can exploit this
  issue by enticing an unsuspecting victim to open a file on a remote SMB
  or WebDAV share.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS11-071.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:1) <= 0){
  exit(0);
}

res = hotfix_missing(name:"2570947");

## MS11-071 Hotfix (2570947)
if(res == 0){
  exit(0);
}

## For XP and 2003 only registry changes
if((hotfix_check_sp(xp:4, win2003:3) == 1) && res == 1)
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath,
                            file_name:"\System32\IME\IMEJP10\Imjpapi.dll");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 2" >< SP)
  {
    if(version_in_range(version:sysVer, test_version:"10.0.6002.18000", test_version2:"10.0.6002.18494")||
       version_in_range(version:sysVer, test_version:"10.0.6002.22000", test_version2:"10.0.6002.22683")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:1) > 0)
{
  if(version_in_range(version:sysVer, test_version:"10.1.7600.16000", test_version2:"10.1.7600.16855")||
     version_in_range(version:sysVer, test_version:"10.1.7600.20000", test_version2:"10.1.7600.21015")||
     version_in_range(version:sysVer, test_version:"10.1.7601.17000", test_version2:"10.1.7601.17657")||
     version_in_range(version:sysVer, test_version:"10.1.7601.21000", test_version2:"10.1.7601.21778")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
