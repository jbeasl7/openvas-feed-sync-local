# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902116");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-02-10 16:06:43 +0100 (Wed, 10 Feb 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0023");
  script_name("Microsoft Client/Server Run-time Subsystem Privilege Elevation Vulnerability (978037)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0344");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38098");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-011");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to monitor all actions
  performed by other logged-in users or run arbitrary code in kernel mode.");
  script_tag(name:"affected", value:"- Microsoft Windows 2000 Service Pack 4 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior");
  script_tag(name:"insight", value:"The issue is caused by an error in the 'Client/Server Run-time Subsystem' (CSRSS)
  that does not properly terminate user processes when a user logs out.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to Microsoft
  Bulletin MS10-011.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3) <= 0){
  exit(0);
}

if(hotfix_missing(name:"978037") == 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\Csrsrv.dll");

sysVer = GetVer(file:file, share:share);
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(win2k:5) > 0)
{
  if(version_is_less(version:sysVer, test_version:"5.0.2195.7366")){
    report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.0.2195.7366");
    security_message(port: 0, data: report);
  }
}
else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"5.1.2600.3657")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.1.2600.3657");
      security_message(port: 0, data: report);
    }
    exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"5.1.2600.5915")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.1.2600.5915");
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
    if(version_is_less(version:sysVer, test_version:"5.2.3790.4635")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.2.3790.4635");
      security_message(port: 0, data: report);
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
