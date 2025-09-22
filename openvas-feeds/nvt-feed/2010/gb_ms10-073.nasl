# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902323");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-10-13 17:10:12 +0200 (Wed, 13 Oct 2010)");
  script_cve_id("CVE-2010-2549", "CVE-2010-2743", "CVE-2010-2744");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Windows Kernel-Mode Drivers Privilege Elevation Vulnerabilities (981957)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2620");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41280");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43773");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43774");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-073");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to run arbitrary
  code in the kernel mode.");
  script_tag(name:"affected", value:"- Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior

  - Microsoft Windows 7");
  script_tag(name:"insight", value:"The flaw is due to an error in the kernel-mode device driver 'Win32k.sys'

  - when handling the reference count for an object.

  - which fails to properly index a table of function pointers when loading a
    keyboard layout from disk.

  - which fails to properly manage a window class.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-073.");
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

if(hotfix_missing(name:"981957") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  sysVer = fetch_file_version(sysPath:sysPath, file_name:"Win32k.sys");
  if(sysVer)
  {
    if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 3" >< SP)
      {
         if(version_is_less(version:sysVer, test_version:"5.1.2600.6033")){
          report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.1.2600.6033", install_path:sysPath);
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
        if(version_is_less(version:sysVer, test_version:"5.2.3790.4769")){
          report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.2.3790.4769", install_path:sysPath);
          security_message(port: 0, data: report);
        }
         exit(0);
      }
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

sysPath = smb_get_system32root();
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"Win32k.sys");
if(!sysVer){
  exit(0);
}
if(hotfix_check_sp(winVista:2, win2008:2) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18523")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"6.0.6001.18523", install_path:sysPath);
      security_message(port: 0, data: report);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18305")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"6.0.6002.18305", install_path:sysPath);
      security_message(port: 0, data: report);
    }
     exit(0);
  }
   security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:1) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.1.7600.16667")){
    report = report_fixed_ver(installed_version:sysVer, fixed_version:"6.1.7600.16667", install_path:sysPath);
    security_message(port: 0, data: report);
  }
}
