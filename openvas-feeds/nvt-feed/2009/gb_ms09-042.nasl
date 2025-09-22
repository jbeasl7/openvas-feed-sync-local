# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900909");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-08-12 19:54:51 +0200 (Wed, 12 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1930");
  script_name("Telnet NTLM Credential Reflection Authentication Bypass Vulnerability (960859)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/960859");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35993");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-042");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code and
  completely compromise the affected computer.");

  script_tag(name:"affected", value:"- Microsoft Windows 2K Service Pack 4 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Vista Service Pack 2 and prior

  - Microsoft Windows 2008 Service Pack 2 and prior");

  script_tag(name:"insight", value:"An error in the Telnet service when handling NTLM authentication can be
  exploited to reflect the user credentials and gain unauthorized access to the affected system.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-042.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

# MS09-042 Hotfix (960859)
if(hotfix_missing(name:"960859") == 0){
  exit(0);
}

exePath = registry_get_sz(item:"Install Path", key:"SOFTWARE\Microsoft\COM3\Setup");
if(!exePath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath + "\telnet.exe");
telnetVer = GetVer(file:file, share:share);
if(!telnetVer){
   exit(0);
}

if(hotfix_check_sp(win2k:5) > 0)
{
  if(version_in_range(version:telnetVer, test_version:"5.0", test_version2:"5.0.33670.3")) {
    report = report_fixed_ver(installed_version:telnetVer, vulnerable_range:"5.0 - 5.0.33670.3");
    security_message(port: 0, data: report);
  }
}

else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_in_range(version:telnetVer, test_version:"5.1", test_version2:"5.1.2600.3586")) {
      report = report_fixed_ver(installed_version:telnetVer, vulnerable_range:"5.1 - 5.1.2600.3586");
      security_message(port: 0, data: report);
    }
     exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    if(version_in_range(version:telnetVer, test_version:"5.1", test_version2:"5.1.2600.5828")) {
      report = report_fixed_ver(installed_version:telnetVer, vulnerable_range:"5.1 - 5.1.2600.5828");
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
    if(version_in_range(version:telnetVer, test_version:"5.2", test_version2:"5.2.3790.4527")) {
      report = report_fixed_ver(installed_version:telnetVer, vulnerable_range:"5.2 - 5.2.3790.4527");
      security_message(port: 0, data: report);
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"PathName");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sysPath + "\System32\telnet.exe");

exeVer = GetVer(file:file, share:share);
if(exeVer)
{
  if(hotfix_check_sp(winVista:3) > 0)
  {
    SP = get_kb_item("SMB/WinVista/ServicePack");
    if("Service Pack 1" >< SP)
    {
      if(version_is_less(version:exeVer, test_version:"6.0.6001.18270")) {
        report = report_fixed_ver(installed_version:exeVer, fixed_version:"6.0.6001.18270");
        security_message(port: 0, data: report);
      }
      exit(0);
    }

    if("Service Pack 2" >< SP)
    {
      if(version_is_less(version:exeVer, test_version:"6.0.6002.18049")) {
        report = report_fixed_ver(installed_version:exeVer, fixed_version:"6.0.6002.18049");
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
      if(version_is_less(version:exeVer, test_version:"6.0.6001.18270")) {
        report = report_fixed_ver(installed_version:exeVer, fixed_version:"6.0.6001.18270");
        security_message(port: 0, data: report);
      }
       exit(0);
    }

    if("Service Pack 2" >< SP)
    {
      if(version_is_less(version:exeVer, test_version:"6.0.6002.18049")) {
        report = report_fixed_ver(installed_version:exeVer, fixed_version:"6.0.6002.18049");
        security_message(port: 0, data: report);
      }
      exit(0);
    }
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
