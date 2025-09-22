# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900667");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-06-10 16:35:14 +0200 (Wed, 10 Jun 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0228", "CVE-2009-0229", "CVE-2009-0230");
  script_name("Vulnerabilities in Print Spooler Could Allow Remote Code Execution (961501)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1541");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35206");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35208");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35209");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-022");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow remote or Local attackers to disclose
  sensitive information or compromise a vulnerable system.");
  script_tag(name:"affected", value:"- Microsoft Windows 2003 Service Pack 2

  - Microsoft Windows 2K Service Pack 4 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior");
  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Buffer overflow error in the Windows Print Spooler when parsing certain
    printing data structures, via a specially crafted RPC request and a
    malicious print server.

  - Error in the Windows Printing Service that does not properly check the files
    that can be included with separator pages.

  - Error in the Windows Print Spooler that does not properly validate the paths
    from which a DLL may be loaded.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-022.");
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

if(hotfix_missing(name:"961501") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  sysVer = fetch_file_version(sysPath:sysPath, file_name:"localspl.dll");
  if(!sysVer){
      exit(0);
  }
}

if(hotfix_check_sp(win2k:5) > 0)
{
    if(version_is_less(version:sysVer, test_version:"5.0.2195.7296")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.0.2195.7296", install_path:sysPath);
      security_message(port: 0, data: report);
  }
   exit(0);
}

else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"5.1.2600.3569")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.1.2600.3569", install_path:sysPath);
      security_message(port: 0, data: report);
    }
    exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"5.1.2600.5809")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.1.2600.5809", install_path:sysPath);
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
    if(version_is_less(version:sysVer, test_version:"5.2.3790.4509")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.2.3790.4509", install_path:sysPath);
      security_message(port: 0, data: report);
    }
     exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"Localspl.dll");
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

