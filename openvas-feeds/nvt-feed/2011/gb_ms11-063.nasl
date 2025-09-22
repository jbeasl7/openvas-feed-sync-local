# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902463");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-08-11 06:41:03 +0200 (Thu, 11 Aug 2011)");
  script_cve_id("CVE-2011-1967");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Client/Server Run-time Subsystem Privilege Escalation Vulnerability (2567680)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow attacker to execute arbitrary code with
  system-level privileges. Successfully exploiting this issue will result in
  the complete compromise of affected computers.");
  script_tag(name:"affected", value:"- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior");
  script_tag(name:"insight", value:"The flaw is due to error in the Client/Server Run-time Subsystem
  (CSRSS) when evaluates inter-process device event message permissions.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-063.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2567680");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48992");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-063");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## MS11-063 Hotfix (2567680)
if(hotfix_missing(name:"2567680") == 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\winsrv.dll");
if(sysVer)
{
  if(hotfix_check_sp(xp:4) > 0)
  {
    SP = get_kb_item("SMB/WinXP/ServicePack");
    if("Service Pack 3" >< SP)
    {
      if(version_is_less(version:sysVer, test_version:"5.1.2600.6125")){
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
      if(version_is_less(version:sysVer, test_version:"5.2.3790.4877")){
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

    if("Service Pack 2" >< SP)
    {
      if(version_in_range(version:sysVer, test_version:"6.0.6002.18000", test_version2:"6.0.6002.18483")||
         version_in_range(version:sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22661")){
       security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
      exit(0);
    }
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

if(hotfix_check_sp(win7:2) > 0)
{
  sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Kernel32.dll");
  if(!sysVer){
    exit(0);
  }

  if(version_in_range(version:sysVer, test_version:"6.1.7600.16000", test_version2:"6.1.7600.16849")||
     version_in_range(version:sysVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21009")||
     version_in_range(version:sysVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17650")||
     version_in_range(version:sysVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21771")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
