# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900567");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2009-06-10 19:23:54 +0200 (Wed, 10 Jun 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1122", "CVE-2009-1535");
  script_name("Microsoft IIS Security Bypass Vulnerability (970483)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl", "gb_microsoft_iis_http_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("IIS/installed", "SMB/registry_enumerated");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/970483");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34993");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35232");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-018");

  script_tag(name:"impact", value:"Remote attackers could exploit this issue to bypass authentication and gain
  unauthorized read and upload access to protected folders.");

  script_tag(name:"affected", value:"- Microsoft Windows 2K  Service Pack 4 and prior

  - Microsoft Windows XP  Service Pack 3 and prior

  - Microsoft Windows 2k3 Service Pack 2 and prior");

  script_tag(name:"insight", value:"The flaw is due to:

  - WebDAV extension does not properly decode requested URLs, which could
  cause an incorrect configuration to be applied.

  - WebDav fails to verify credentials before accessing password-protected
  resources when handling HTTP GET or PROPFIND requests containing a Unicode
  encoded character with a 'Translate: f' header.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-020.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-020");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3) <= 0){
  exit(0);
}

if(hotfix_missing(name:"970483") == 0){
  exit(0);
}

httpPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup", item:"Install Path");
if(!httpPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:httpPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:httpPath + "\inetsrv\httpext.dll");

httpVer = GetVer(file:file, share:share);
if(!httpVer){
  exit(0);
}

if(hotfix_check_sp(win2k:5) > 0)
{
  if(version_in_range(version:httpVer, test_version:"5.0", test_version2:"5.0.2195.7289")) {
    report = report_fixed_ver(installed_version:httpVer, vulnerable_range:"5.0 - 5.0.2195.7289");
    security_message(port: 0, data: report);
  }
}

else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_in_range(version:httpVer, test_version:"6.0", test_version2:"6.0.3790.4517")) {
      report = report_fixed_ver(installed_version:httpVer, vulnerable_range:"6.0 - 6.0.3790.4517");
      security_message(port: 0, data: report);
    }
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_in_range(version:httpVer, test_version:"6.0", test_version2:"6.0.2600.3573")) {
      report = report_fixed_ver(installed_version:httpVer, vulnerable_range:"6.0 - 6.0.2600.3573");
      security_message(port: 0, data: report);
    }
  }
  else if("Service Pack 3" >< SP)
  {
    if(version_in_range(version:httpVer, test_version:"6.0", test_version2:"6.0.2600.5816")) {
      report = report_fixed_ver(installed_version:httpVer, vulnerable_range:"6.0 - 6.0.2600.5816");
      security_message(port: 0, data: report);
    }
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
