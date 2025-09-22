# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806659");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-0002", "CVE-2016-0005");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:10:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-01-13 09:07:29 +0530 (Wed, 13 Jan 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (3124903)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-001.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error due to improper handling of objects in memory,

  - Improper enforcing of cross-domain policies.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code and gain elevated privileges on the affected
  system.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 7.x/8.x/9.x/10.x/11.x.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3124903");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3124275");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3124263");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-001");

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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2,
                   win8:1, win8x64:1, win2012:1,  win2012R2:1, win8_1:1, win8_1x64:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

ieVer = get_app_version(cpe:CPE);
if(!ieVer || ieVer !~ "^([7-9|1[01])\."){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Mshtml.dll");
if(!dllVer){
  exit(0);
}

if(dllVer =~ "^7\.0\.6002\.1"){
  Vulnerable_range = "7.0.6002.18000 - 7.0.6002.19566";
}
else if (dllVer =~ "^7\.0\.6002\.2"){
  Vulnerable_range = "7.0.6002.23000 - 7.0.6002.23877";
}
else if (dllVer =~ "^8\.0\.6001\.1"){
  Vulnerable_range = "8.0.6001.18000 - 8.0.6001.19726";
}
else if (dllVer =~ "^8\.0\.6001\.2"){
  Vulnerable_range = "8.0.6001.20000 - 8.0.6001.23785";
}
else if (dllVer =~ "^9\.0\.8112\.1"){
  Vulnerable_range = "9.0.8112.16000 - 9.0.8112.16736";
}
else if (dllVer =~ "^9\.0\.8112\.2"){
  Vulnerable_range = "9.0.8112.20000 - 9.0.8112.20851";
}
else if (dllVer =~ "^8\.0\.7601\.1"){
  Vulnerable_range = "8.0.7601.17000 - 8.0.7601.19103";
}
else if (dllVer =~ "^8\.0\.7601\.2"){
  Vulnerable_range = "8.0.7601.22000 - 8.0.7601.23300";
}

if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.19566")||
     version_in_range(version:dllVer, test_version:"7.0.6002.23000", test_version2:"7.0.6002.23877")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19726")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23785")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16736")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20851")){
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_in_range(version:dllVer, test_version:"8.0.7601.17000", test_version2:"8.0.7601.19103")||
     version_in_range(version:dllVer, test_version:"8.0.7601.22000", test_version2:"8.0.7601.23300")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16736")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20851")){
    VULN = TRUE ;
  }

  else if(version_in_range(version:dllVer, test_version:"11.0.9600.00000", test_version2:"11.0.9600.18162"))
  {
     Vulnerable_range = "11.0.9600.00000 - 11.0.9600.18162";
     VULN = TRUE ;
  }

  ##For IE 10 Version differ based on architecture
  else if(hotfix_check_sp(win7:2) > 0)
  {
    if(version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.17608"))
    {
      Vulnerable_range = "10.0.9200.16000 - 10.0.9200.17608";
      VULN = TRUE ;
    }

    else if(version_in_range(version:dllVer, test_version:"10.0.9200.21000", test_version2:"10.0.9200.21727"))
    {
      Vulnerable_range = "10.0.9200.21000 - 10.0.9200.21727";
      VULN = TRUE ;
    }
  }
  else if (hotfix_check_sp(win7x64:2, win2008r2:2) > 0)
  {
    if(version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.17605"))
    {
      Vulnerable_range = "10.0.9200.16000 - 10.0.9200.17605";
      VULN = TRUE ;
    }

    else if(version_in_range(version:dllVer, test_version:"10.0.9200.21000", test_version2:"10.0.9200.21725"))
    {
      Vulnerable_range = "10.0.9200.21000 - 10.0.9200.21725";
      VULN = TRUE ;
    }
  }
}

else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  if(version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.17605"))
  {
    Vulnerable_range = "10.0.9200.16000 - 10.0.9200.17605";
    VULN = TRUE ;
  }
  else if(version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.21725"))
  {
    Vulnerable_range = "10.0.9200.20000 - 10.0.9200.21725";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"11.0.9600.18161"))
  {
    Vulnerable_range = "Less than 11.0.9600.18161";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"11.0.10240.16644"))
  {
    Vulnerable_range = "Less than 11.0.10240.16644";
    VULN = TRUE ;
  }

  else if(version_in_range(version:dllVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.34"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.34";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\system32\Mshtml.dll" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
