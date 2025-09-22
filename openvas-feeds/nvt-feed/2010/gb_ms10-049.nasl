# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900247");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-08-11 15:08:29 +0200 (Wed, 11 Aug 2010)");
  script_cve_id("CVE-2009-3555");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Remote Code Execution Vulnerabilities in SChannel (980436)");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54158");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36935");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-049");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation of this issue may allow attackers to perform limited
  man-in-the-middle attacks to inject data into the beginning of the
  application protocol stream to execute HTTP transactions, bypass
  authentication.");
  script_tag(name:"affected", value:"- Microsoft Windows 7

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior");
  script_tag(name:"insight", value:"A flaw exists in the Microsoft Windows SChannel (Secure Channel)
  authentication component when using certificate based authentication, which
  allows spoofing.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-049.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win7:1, win2008:3) <= 0){
  exit(0);
}

if(hotfix_missing(name:"980436") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"Schannel.dll");
  if(!dllVer){
    exit(0);
  }
}

if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"5.1.2600.6006")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"5.1.2600.6006", install_path:sysPath);
      security_message(port: 0, data: report);
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"5.2.3790.4724")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"5.2.3790.4724", install_path:sysPath);
      security_message(port: 0, data: report);
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"Schannel.dll");
  if(!dllVer){
    exit(0);
  }
}

if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18490")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6001.18490", install_path:sysPath);
      security_message(port: 0, data: report);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
      if(version_is_less(version:dllVer, test_version:"6.0.6002.18269")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6002.18269", install_path:sysPath);
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
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18490")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6001.18490", install_path:sysPath);
      security_message(port: 0, data: report);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6002.18269")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6002.18269", install_path:sysPath);
      security_message(port: 0, data: report);
    }
    exit(0);
  }
 security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.1.7600.16612")){
     report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.1.7600.16612", install_path:sysPath);
     security_message(port: 0, data: report);
  }
}

