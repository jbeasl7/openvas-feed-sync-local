# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902321");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-10-13 17:10:12 +0200 (Wed, 13 Oct 2010)");
  script_cve_id("CVE-2010-1883");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Embedded OpenType Font Engine Remote Code Execution Vulnerability (982132)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2623");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43775");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-076");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code by tricking a user into visiting a malicious web page or opening a
  specially crafted email or Office document.");
  script_tag(name:"affected", value:"- Microsoft Windows 7

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior");
  script_tag(name:"insight", value:"The flaw is due to an integer overflow error in the Embedded OpenType
  Font Engine when parsing certain tables within specially crafted files and
  content containing embedded fonts.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-076.");
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

if(hotfix_missing(name:"982132") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"t2embed.dll");
  if(dllVer)
  {
    if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 3" >< SP)
      {
         if(version_is_less(version:dllVer, test_version:"5.1.2600.6031")){
          report = report_fixed_ver(installed_version:dllVer, fixed_version:"5.1.2600.6031", install_path:sysPath);
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
        if(version_is_less(version:dllVer, test_version:"5.2.3790.4766")){
          report = report_fixed_ver(installed_version:dllVer, fixed_version:"5.2.3790.4766", install_path:sysPath);
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

dllVer = fetch_file_version(sysPath:sysPath, file_name:"t2embed.dll");
if(!dllVer){
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
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18520")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6001.18520", install_path:sysPath);
      security_message(port: 0, data: report);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6002.18301")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6002.18301", install_path:sysPath);
      security_message(port: 0, data: report);
    }
    exit(0);
  }
   security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.1.7600.16663")){
    report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.1.7600.16663", install_path:sysPath);
    security_message(port: 0, data: report);
  }
}
