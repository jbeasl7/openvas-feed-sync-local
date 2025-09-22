# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810696");
  script_version("2024-07-04T05:05:37+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-0162");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-07-04 05:05:37 +0000 (Thu, 04 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-02 12:20:10 +0000 (Tue, 02 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-04-13 16:08:47 +0530 (Thu, 13 Apr 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Internet Explorer Information Disclosure Vulnerability (3148531)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-037.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when Internet Explorer
  does not properly handle JavaScript.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information on the affected
  system.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 9.x/10.x/11.x.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3148531");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/85939");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4014661");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-037");
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

if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3, win2012:1,
                   win7:2, win7x64:2, win2008r2:2, win8_1:1, win8_1x64:1,
                   win2012R2:1) <= 0){
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

iedllVer = fetch_file_version(sysPath:iePath, file_name:"Mshtml.dll");
if(!iedllVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3, win2008:3, winVistax64:3, win2008x64:3) > 0)
{
  if(version_in_range(version:iedllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16871"))
  {
    Vulnerable_range = "9.0.8112.16000 - 9.0.8112.16871";
    VULN = TRUE ;
  }
  else if(version_in_range(version:iedllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20985"))
  {
    Vulnerable_range = "9.0.8112.20000 - 9.0.8112.20985";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_in_range(version:iedllVer, test_version:"11.0.9600.00000", test_version2:"11.0.9600.18638"))
  {
     Vulnerable_range = "11.0.9600.00000 - 11.0.9600.18280";
     VULN = TRUE ;
  }
}

## Tested on Win 2012
else if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_in_range(version:iedllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.22120"))
  {
    Vulnerable_range = "10.0.9200.16000 - 10.0.9200.22120";
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
