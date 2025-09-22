# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804739");
  script_version("2024-07-01T05:05:39+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-2774", "CVE-2014-2784", "CVE-2014-2796", "CVE-2014-2808",
                "CVE-2014-2810", "CVE-2014-2811", "CVE-2014-2817", "CVE-2014-2818",
                "CVE-2014-2819", "CVE-2014-2820", "CVE-2014-2821", "CVE-2014-2822",
                "CVE-2014-2823", "CVE-2014-2824", "CVE-2014-2825", "CVE-2014-2826",
                "CVE-2014-2827", "CVE-2014-4050", "CVE-2014-4051", "CVE-2014-4052",
                "CVE-2014-4055", "CVE-2014-4056", "CVE-2014-4057", "CVE-2014-4058",
                "CVE-2014-4063", "CVE-2014-4067", "CVE-2014-4078", "CVE-2014-6354",
                "CVE-2014-4145", "CVE-2014-8985", "CVE-2014-4112", "CVE-2014-4066");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-01 05:05:39 +0000 (Mon, 01 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-28 17:29:38 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-08-13 07:44:02 +0530 (Wed, 13 Aug 2014)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (2976627)");

  script_tag(name:"summary", value:"This host is missing a critical security update according to Microsoft
  Bulletin MS14-051.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws are due to multiple unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execution of arbitrary code
  and compromise a user's system.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 6.x/7.x/8.x/9.x/10.x/11.x.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2976627");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69090");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69092");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69095");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69100");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69101");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69103");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69104");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69106");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69115");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69116");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69117");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69118");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69119");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69120");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69121");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69122");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69124");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69125");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69126");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69127");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69128");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69129");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69130");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69131");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69132");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69134");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70578");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70937");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72593");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS14-051");
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
  if(version_is_less(version:dllVer, test_version:"6.0.3790.5392") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.21396")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.23610")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.19142")||
     version_in_range(version:dllVer, test_version:"7.0.6002.23000", test_version2:"7.0.6002.23445")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19552")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23610")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16562")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20673")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_in_range(version:dllVer, test_version:"8.0.7601.18000", test_version2:"8.0.7601.18533")||
     version_in_range(version:dllVer, test_version:"8.0.7601.22000", test_version2:"8.0.7601.22744")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16562")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20673")||
     version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.17053")||
     version_in_range(version:dllVer, test_version:"10.0.9200.21000", test_version2:"10.0.9200.21172")||
     version_in_range(version:dllVer, test_version:"11.0.9600.00000", test_version2:"11.0.9600.17238")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  if(version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.17053")||
     version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.21172")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"11.0.9600.17239")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
