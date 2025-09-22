# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900588");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-07-15 20:20:16 +0200 (Wed, 15 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1537", "CVE-2009-1538", "CVE-2009-1539");
  script_name("Microsoft DirectShow Remote Code Execution Vulnerability (961373)");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-028");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35139");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Attackers cam exploit this issue to execute arbitrary code and to potentially
  compromise a user's system.");
  script_tag(name:"affected", value:"DirectX 7.0, 8.1 and 9.0 on Microsoft Windows 2000
  DirectX 9.0 on Microsoft Windows XP and 2003");
  script_tag(name:"insight", value:"- An unspecified error in QuickTime Movie Parser Filter in quartz.dll while
    processing malicious QuickTime media files may lead to memory corruption.

  - Lack of validation while updating a pointer could allow code execution
    via a specially crafted QuickTime file.

  - An error while validating certain size fields during processing of
    QuickTime media files can be exploited to corrupt memory.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-028.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

# OS with Hotfix Check
if(hotfix_check_sp(win2k:5, xp:4, win2003:3) <= 0){
  exit(0);
}

directXver = registry_get_sz(key:"SOFTWARE\Microsoft\DirectX", item:"Version");
if(!egrep(pattern:"^4\.0[789]\..*", string:directXver)){
  exit(0);
}

# MS09-011 Hotfix check
if(hotfix_missing(name:"971633") == 0){
  exit(0);
}

dllFile = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!dllFile){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllFile);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:dllFile + "\quartz.dll");

dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(win2k:5) > 0)
{
  if(directXver =~ "^4\.07")
  {
     if(version_is_less(version:dllVer, test_version:"6.1.9.736")){
       report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.1.9.736");
       security_message(port: 0, data: report);
     }
  }
  else if(directXver =~ "^4\.08")
  {
    if(version_is_less(version:dllVer, test_version:"6.3.1.893")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.3.1.893");
      security_message(port: 0, data: report);
    }
  }
  else if(directXver =~ "^4\.09")
  {
    if(version_is_less(version:dllVer, test_version:"6.5.1.911")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.5.1.911");
      security_message(port: 0, data: report);
    }
  }
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  if(directXver =~ "^4\.09")
  {
    SP = get_kb_item("SMB/WinXP/ServicePack");
    if("Service Pack 2" >< SP)
    {
      if(version_is_less(version:dllVer, test_version:"6.5.2600.3580")){
        report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.5.2600.3580");
        security_message(port: 0, data: report);
      }
    }
    else if("Service Pack 3" >< SP)
    {
      if(version_is_less(version:dllVer, test_version:"6.5.2600.5822")){
        report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.5.2600.5822");
        security_message(port: 0, data: report);
      }
    }
  }
  exit(0);
}

if(hotfix_check_sp(win2003:3) > 0)
{
  if(directXver =~ "^4\.09")
  {
    SP = get_kb_item("SMB/Win2003/ServicePack");
    if("Service Pack 2" >< SP)
    {
      if(version_is_less(version:dllVer, test_version:"6.5.3790.4523")){
        report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.5.3790.4523");
        security_message(port: 0, data: report);
      }
    }
  }
}
