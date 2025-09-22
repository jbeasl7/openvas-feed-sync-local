# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807899");
  script_version("2023-07-20T05:05:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-3267", "CVE-2016-3298", "CVE-2016-3331", "CVE-2016-3382",
                "CVE-2016-3383", "CVE-2016-3384", "CVE-2016-3385", "CVE-2016-3387",
                "CVE-2016-3388", "CVE-2016-3390", "CVE-2016-3391");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:12:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-10-12 08:21:08 +0530 (Wed, 12 Oct 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (3192887)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-118.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An improper way of accessing objects in memory.

  - An error in the way that the Scripting Engine renders when handling objects
    in memory in Microsoft browsers.

  - An error when Internet Explorer or Edge fails to properly secure private
    namespace.

  - An error when Internet Explorer or Edge does not properly handle objects
    in memory.

  - An error when Microsoft browsers leave credential data in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the current user, also
  could gain the same user rights as the current user, and obtain information
  to further compromise the user's system.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 9.x/10.x/11.x.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3192887");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93376");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93386");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93387");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93397");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93396");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93382");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93383");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93393");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93392");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93379");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93381");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-118");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(hotfix_check_sp(winVista:3, winVistax64:3, win2008x64:3, win7:2, win7x64:2, win2008:3, win2008r2:2,
                   win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

ieVer = get_app_version(cpe:CPE);
if(!ieVer || ieVer !~ "^(9|1[01])\."){
  exit(0);
}

iePath = smb_get_system32root();
if(!iePath ){
  exit(0);
}

iedllVer = fetch_file_version(sysPath:iePath, file_name:"mshtml.dll");
edgedllVer = fetch_file_version(sysPath:iePath, file_name:"edgehtml.dll");
if(!iedllVer && !edgedllVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3, win2008:3, winVistax64:3, win2008x64:3) > 0)
{
  if(version_in_range(version:iedllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16829"))
  {
    Vulnerable_range = "9.0.8112.16000 - 9.0.8112.16829";
    VULN = TRUE ;
  }
  else if(version_in_range(version:iedllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20946"))
  {
    Vulnerable_range = "9.0.8112.20000 - 9.0.8112.20946";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_in_range(version:iedllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.21988"))
  {
    Vulnerable_range = "10.0.9200.16000 - 10.0.9200.21988";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1, win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_in_range(version:iedllVer, test_version:"11.0.9600.00000", test_version2:"11.0.9600.18499"))
  {
     Vulnerable_range = "11.0.9600.00000 - 11.0.9600.18499";
     VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:iedllVer, test_version:"11.0.10240.17146"))
  {
    Vulnerable_range = "Less than 11.0.10240.17146";
    VULN = TRUE ;
  }

  ## AS Windows 10 has commulative update, checking for 'system32/edgehtml.dll' file < 11.0.10586.633
  else if(version_in_range(version:edgedllVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.632"))
  {
    Vulnerable_range2 = "11.0.10586.0 - 11.0.10586.632";
    VULN2 = TRUE ;
  }

  else if(version_in_range(version:edgedllVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.320"))
  {
    Vulnerable_range2 = "11.0.14393.0 - 11.0.14393.320";
    VULN2 = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + iePath + "\mshtml.dll" + '\n' +
           'File version:     ' + iedllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
 exit(0);
}

if(VULN2)
{
  report = 'File checked:     ' + iePath + "\edgehtml.dll" + '\n' +
           'File version:     ' + edgedllVer + '\n' +
           'Vulnerable range: ' + Vulnerable_range2 + '\n' ;
  security_message(data:report);
  exit(0);
}
