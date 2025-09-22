# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802081");
  script_version("2023-07-27T05:05:08+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-7331", "CVE-2014-2799", "CVE-2014-4059", "CVE-2014-4065",
                "CVE-2014-4079", "CVE-2014-4080", "CVE-2014-4081", "CVE-2014-4082",
                "CVE-2014-4083", "CVE-2014-4084", "CVE-2014-4085", "CVE-2014-4086",
                "CVE-2014-4087", "CVE-2014-4088", "CVE-2014-4089", "CVE-2014-4090",
                "CVE-2014-4091", "CVE-2014-4092", "CVE-2014-4093", "CVE-2014-4094",
                "CVE-2014-4095", "CVE-2014-4096", "CVE-2014-4097", "CVE-2014-4098",
                "CVE-2014-4099", "CVE-2014-4100", "CVE-2014-4101", "CVE-2014-4102",
                "CVE-2014-4103", "CVE-2014-4104", "CVE-2014-4105", "CVE-2014-4106",
                "CVE-2014-4107", "CVE-2014-4108", "CVE-2014-4109", "CVE-2014-4110",
                "CVE-2014-4111");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-10 09:49:48 +0530 (Wed, 10 Sep 2014)");
  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (2977629)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS14-052.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error within the XMLDOM ActiveX control.

  - Multiple unspecified vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclose certain sensitive information and compromise a user's system.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 6.x/7.x/8.x/9.x/10.x/11.x.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2977629");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65601");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69576");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69578");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69580");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69581");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69583");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69584");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69585");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69587");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69588");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69589");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69590");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69591");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69595");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69596");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69597");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69598");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69599");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69600");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69601");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69602");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69605");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69606");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69607");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69608");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69609");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69610");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69611");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69612");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69613");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69614");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69615");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69616");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69617");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69618");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69619");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS14-052");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2, win7x64:2,
                   win2008:3, win2008r2:2, win8:1, win8x64:1, win2012:1,
                   win2012R2:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

ieVer = get_app_version(cpe:CPE);
if(!ieVer || ieVer !~ "^([6-9|1[01])\."){
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

if(hotfix_check_sp(win2003:3, win2003x64:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.3790.5413") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.21407")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.23618")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.19164")||
     version_in_range(version:dllVer, test_version:"7.0.6002.23000", test_version2:"7.0.6002.23469")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19560")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23618")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16574")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20690")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_in_range(version:dllVer, test_version:"8.0.7601.18000", test_version2:"8.0.7601.18570")||
     version_in_range(version:dllVer, test_version:"8.0.7601.22000", test_version2:"8.0.7601.22776")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16574")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20690")||
     version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.17087")||
     version_in_range(version:dllVer, test_version:"10.0.9200.21000", test_version2:"10.0.9200.21206")||
     version_in_range(version:dllVer, test_version:"11.0.9600.00000", test_version2:"11.0.9600.17279")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  if(version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.17087")||
     version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.21206")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"11.0.9600.17278")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
