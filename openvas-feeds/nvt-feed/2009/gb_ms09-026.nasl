# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900668");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-06-10 16:35:14 +0200 (Wed, 10 Jun 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0568");
  script_name("Vulnerability in RPC Could Allow Elevation of Privilege (970238)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1545");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-026");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow remote or local attackers to execute
  arbitrary code by sending specially crafted RPC message to a vulnerable
  third-party RPC application.");
  script_tag(name:"affected", value:"- Microsoft Windows 2K Service Pack 4 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior");
  script_tag(name:"insight", value:"The flaws occurs because the Remote Procedure Call (RPC) Marshalling Engine
  does not updating its internal state in an appropriate manner.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-026.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

if(hotfix_missing(name:"970238") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  sysVer = fetch_file_version(sysPath:sysPath, file_name:"Rpcrt4.dll");
  if(!sysVer){
      exit(0);
  }
}

if(hotfix_check_sp(win2k:5) > 0)
{
    if(version_is_less(version:sysVer, test_version:"5.0.2195.7281")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.0.2195.7281", install_path:sysPath);
      security_message(port: 0, data: report);
  }
   exit(0);
}

else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"5.1.2600.3555")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.1.2600.3555", install_path:sysPath);
      security_message(port: 0, data: report);
    }
     exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"5.1.2600.5795")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.1.2600.5795", install_path:sysPath);
      security_message(port: 0, data: report);
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
    if(version_is_less(version:sysVer, test_version:"5.2.3790.4502")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.2.3790.4502", install_path:sysPath);
      security_message(port: 0, data: report);
    }
      exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"Rpcrt4.dll");
  if(!dllVer){
    exit(0);
  }
}

if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18247")){
        report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6001.18247", install_path:sysPath);
        security_message(port: 0, data: report);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
      if(version_is_less(version:dllVer, test_version:"6.0.6002.18024")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6002.18024", install_path:sysPath);
      security_message(port: 0, data: report);
    }
     exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win2008:3) > 0)
{
  SP = get_kb_item("SMB/Win2008/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18247")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6001.18247", install_path:sysPath);
      security_message(port: 0, data: report);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6002.18024")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6002.18024", install_path:sysPath);
      security_message(port: 0, data: report);
    }
    exit(0);
  }
 security_message( port: 0, data: "The target host was found to be vulnerable" );
}

