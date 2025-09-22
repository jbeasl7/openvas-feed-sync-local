# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811032");
  script_version("2024-07-25T05:05:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-0064", "CVE-2017-0222", "CVE-2017-0226", "CVE-2017-0228",
                "CVE-2017-0231", "CVE-2017-0238");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-25 05:05:41 +0000 (Thu, 25 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 16:19:54 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-05-10 12:38:44 +0530 (Wed, 10 May 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (KB4018271)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft security updates KB4018271.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in the way JavaScript scripting engines handle objects in memory
  in Microsoft browsers.

  - An error when Microsoft browsers render SmartScreen Filter.

  - An error when Internet Explorer improperly accesses objects in memory.

  - An unspecified error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to trick a user by redirecting the user to a specially crafted website, loading
  of unsecure content (HTTP) from secure locations (HTTPS) and to execute
  arbitrary code in the context of the current user.If the current user is logged
  on with administrative user rights, an attacker who successfully exploited the
  vulnerability could take control of an affected system. An attacker could then
  install programs, view, change, or delete data or create new accounts with full
  user rights.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 9.x, 10.x and 11.x.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4018271");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98121");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98127");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98139");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98164");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98173");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98237");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0222");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0064");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0226");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0228");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0231");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0238");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/IE/Version");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, winVistax64:3,
                   win2008:3, win2008x64:3, win7:2, win7x64:2, win2008r2:2, win8:1,
                   win8x64:1, win2012:1,  win2012R2:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

ieVer = get_app_version(cpe:CPE);
if(!ieVer || ieVer !~ "^([89|1[01])\."){
  exit(0);
}

iePath = smb_get_system32root();
if(!iePath ){
  exit(0);
}

iedllVer = fetch_file_version(sysPath:iePath, file_name:"Mshtml.dll");
if(!iedllVer){
  exit(0);
}


##Server 2008 and vista
if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0)
{
  if(version_in_range(version:iedllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16895"))
  {
    Vulnerable_range = "9.0.8112.16000 - 9.0.8112.16895";
    VULN = TRUE ;
  }
  else if(version_in_range(version:iedllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.21006"))
  {
    Vulnerable_range = "9.0.8112.20000 - 9.0.8112.21006";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(xp:4, win2003:3, win2003x64:3, xpx64:3) > 0)
{
  if(version_is_less(version:iedllVer, test_version:"8.0.6001.23942"))
  {
    Vulnerable_range = "Less than 8.0.6001.23942";
    VULN = TRUE ;
  }
}

# Win 2012, Win 8
else if(hotfix_check_sp(win2012:1, win8:1, win8x64:1) > 0)
{
  if(version_is_less(version:iedllVer, test_version:"10.0.9200.22137"))
  {
    Vulnerable_range = "Less than 10.0.9200.22137";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1, win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:iedllVer, test_version:"11.0.9600.18666"))
  {
     Vulnerable_range = "Less than 11.0.9600.18666";
     VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + iePath + "\Mshtml.dll" + '\n' +
           'File version:     ' + iedllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
