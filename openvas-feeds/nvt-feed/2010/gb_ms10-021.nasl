# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900236");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-04-14 17:51:53 +0200 (Wed, 14 Apr 2010)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0234", "CVE-2010-0235", "CVE-2010-0236", "CVE-2010-0237",
                "CVE-2010-0238", "CVE-2010-0481", "CVE-2010-0482", "CVE-2010-0810");
  script_name("Microsoft Windows Kernel Could Allow Elevation of Privilege (979683)");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-021");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39297");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39309");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39318");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39319");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39320");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39322");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39323");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39324");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow local users to cause a Denial of Service
  or gain escalated privileges.");

  script_tag(name:"affected", value:"- Microsoft Windows 7

  - Microsoft Windows 2K  Service Pack 4 and prior

  - Microsoft Windows XP  Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior");

  script_tag(name:"insight", value:"Multiple errors exist in the Windows kernel due to:

  - the way that the kernel handles certain exceptions

  - improper validation of specially crafted image files

  - the manner in which the kernel processes the values of symbolic links

  - insufficient validation of registry keys passed to a Windows kernel system
    call

  - the manner in which memory is allocated when extracting a symbolic link
    from a registry key

  - the way that the kernel resolves the real path for a registry key from its
    virtual path

  - not properly restricting symbolic link creation between untrusted and
    trusted registry hives");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS10-021.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3, win7:1, win2008:3) <= 0){
  exit(0);
}

## MS10-021 Hotfix check
if(hotfix_missing(name:"979683") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  exeVer = fetch_file_version(sysPath:sysPath, file_name:"ntoskrnl.exe");
  if(!exeVer){
    exit(0);
  }
}

if(hotfix_check_sp(win2k:5) > 0)
{
  if(version_is_less(version:exeVer, test_version:"5.0.2195.7376")){
    report = report_fixed_ver(installed_version:exeVer, fixed_version:"5.0.2195.7376", install_path:sysPath);
    security_message(port: 0, data: report);
  }
}

else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:exeVer, test_version:"5.1.2600.3670")){
      report = report_fixed_ver(installed_version:exeVer, fixed_version:"5.1.2600.3670", install_path:sysPath);
      security_message(port: 0, data: report);
    }
    exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    if(version_is_less(version:exeVer, test_version:"5.1.2600.5938")){
      report = report_fixed_ver(installed_version:exeVer, fixed_version:"5.1.2600.5938", install_path:sysPath);
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
    if(version_is_less(version:exeVer, test_version:"5.2.3790.4666")){
      report = report_fixed_ver(installed_version:exeVer, fixed_version:"5.2.3790.4666", install_path:sysPath);
      security_message(port: 0, data: report);
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

sysPath = smb_get_system32root();
if(sysPath)
{
  exeVer = fetch_file_version(sysPath:sysPath, file_name:"ntoskrnl.exe");
  if(!exeVer){
    exit(0);
  }
}
if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:exeVer, test_version:"6.0.6001.18427")){
      report = report_fixed_ver(installed_version:exeVer, fixed_version:"6.0.6001.18427", install_path:sysPath);
      security_message(port: 0, data: report);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
      if(version_is_less(version:exeVer, test_version:"6.0.6002.18209")){
      report = report_fixed_ver(installed_version:exeVer, fixed_version:"6.0.6002.18209", install_path:sysPath);
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
    if(version_is_less(version:exeVer, test_version:"6.0.6001.18427")){
       report = report_fixed_ver(installed_version:exeVer, fixed_version:"6.0.6001.18427", install_path:sysPath);
       security_message(port: 0, data: report);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:exeVer, test_version:"6.0.6002.18209")){
       report = report_fixed_ver(installed_version:exeVer, fixed_version:"6.0.6002.18209", install_path:sysPath);
       security_message(port: 0, data: report);
    }
     exit(0);
  }
 security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:1) > 0)
{
  if(version_is_less(version:exeVer, test_version:"6.1.7600.16539")){
     report = report_fixed_ver(installed_version:exeVer, fixed_version:"6.1.7600.16539", install_path:sysPath);
     security_message(port: 0, data: report);
  }
}

