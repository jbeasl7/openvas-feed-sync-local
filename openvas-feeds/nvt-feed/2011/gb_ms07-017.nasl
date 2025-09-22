# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801720");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2011-01-14 09:03:25 +0100 (Fri, 14 Jan 2011)");
  script_cve_id("CVE-2007-0038", "CVE-2007-1211", "CVE-2007-1212",
                "CVE-2007-1213", "CVE-2007-1215");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Vulnerabilities in GDI Could Allow Remote Code Execution (925902)");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/33258");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23273");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23275");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23276");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23278");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/33301");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2007/Apr/1017845.html");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-017");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code.");
  script_tag(name:"affected", value:"- Microsoft Windows XP Service Pack 2 and prior

  - Microsoft Windows 2000 Service Pack 4 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista");
  script_tag(name:"insight", value:"The flaw is due to

  - A boundary error within the handling of animated cursors

  - Invalid memory reference.

  - Privilege escalation vulnerability when rendering malformed 'EMF'
    image files.

  - Error in Windows TrueType Font Rasterizer.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS07-017.");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:3, win2003:3, winVista:3) <= 0){
  exit(0);
}

if(hotfix_missing(name:"925902") == 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  sysVer = fetch_file_version(sysPath:sysPath, file_name:"win32k.sys");
  if(sysVer)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      if(version_is_less(version:sysVer, test_version:"5.0.2195.7133")){
        report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.0.2195.7133");
        security_message(port: 0, data: report);
      }
    }

    else if(hotfix_check_sp(xp:3) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
         if(version_is_less(version:sysVer, test_version:"5.1.2600.3099")){
          report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.1.2600.3099");
          security_message(port: 0, data: report);
        }
         exit(0);
      }
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }

    else if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP)
      {
        if(version_is_less(version:sysVer, test_version:"5.2.3790.2892")){
          report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.2.3790.2892");
          security_message(port: 0, data: report);
        }
         exit(0);
      }
      if("Service Pack 2" >< SP)
      {
        if(version_is_less(version:sysVer, test_version:"5.2.3790.4033")){
          report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.2.3790.4033");
          security_message(port: 0, data: report);
        }
         exit(0);
      }
       security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                      item:"PathName");
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\win32k.sys");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.0.6000.16438")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"6.0.6000.16438");
      security_message(port: 0, data: report);
  }
  exit(0);
}
