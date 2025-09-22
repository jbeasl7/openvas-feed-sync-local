# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902067");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-06-09 17:19:57 +0200 (Wed, 09 Jun 2010)");
  script_cve_id("CVE-2010-0484", "CVE-2010-0485", "CVE-2010-1255");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_name("Microsoft Windows Kernel Mode Drivers Privilege Escalation Vulnerabilities (979559)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1389");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40508");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40569");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40570");
  script_xref(name:"URL", value:"http://www.us-cert.gov/cas/techalerts/TA10-159B.html");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-032");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code
  with kernel privileges.");

  script_tag(name:"affected", value:"- Microsoft Windows 7

  - Microsoft Windows 2K  Service Pack 4 and prior

  - Microsoft Windows XP  Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior");

  script_tag(name:"insight", value:"The flaws are due to an error in the kernel-mode device driver 'Win32k.sys', which

  - does not properly validate changes in certain 'kernel objects'.

  - does not properly validate all callback parameters when creating a
    'new window' or

  - when providing 'glyph' outline information to applications.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-032.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:3, win7:1, win2008:3) <= 0){
  exit(0);
}

## MS10-032 Hotfix check
if(hotfix_missing(name:"979559") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  sysVer = fetch_file_version(sysPath:sysPath, file_name:"Win32k.sys");
  if(!sysVer){
    exit(0);
  }
}

if(hotfix_check_sp(win2k:5) > 0)
{
  if(version_is_less(version:sysVer, test_version:"5.0.2195.7397")){
    report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.0.2195.7397", install_path:sysPath);
    security_message(port: 0, data: report);
  }
}

else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP )
  {
    if(version_is_less(version:sysVer, test_version:"5.1.2600.3706")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.1.2600.3706", install_path:sysPath);
      security_message(port: 0, data: report);
    }
     exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
     if(version_is_less(version:sysVer, test_version:"5.1.2600.5976")){
       report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.1.2600.5976", install_path:sysPath);
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
    if(version_is_less(version:sysVer, test_version:"5.2.3790.4702")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.2.3790.4702", install_path:sysPath);
      security_message(port: 0, data: report);
    }
     exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

sysPath = smb_get_system32root();
if(sysPath)
{
  sysVer = fetch_file_version(sysPath:sysPath, file_name:"Win32k.sys");
  if(!sysVer){
   exit(0);
  }
}

if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18468")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"6.0.6001.18468", install_path:sysPath);
      security_message(port: 0, data: report);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
      if(version_is_less(version:sysVer, test_version:"6.0.6002.18253")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"6.0.6002.18253", install_path:sysPath);
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
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18468")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"6.0.6001.18468", install_path:sysPath);
      security_message(port: 0, data: report);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18253")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"6.0.6002.18253", install_path:sysPath);
      security_message(port: 0, data: report);
    }
      exit(0);
  }
 security_message( port: 0, data: "The target host was found to be vulnerable" );
}

if(hotfix_check_sp(win7:1) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.1.7600.16585")){
     report = report_fixed_ver(installed_version:sysVer, fixed_version:"6.1.7600.16585", install_path:sysPath);
     security_message(port: 0, data: report);
  }
}


