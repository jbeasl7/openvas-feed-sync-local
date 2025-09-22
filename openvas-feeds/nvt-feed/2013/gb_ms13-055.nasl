# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903314");
  script_version("2025-01-21T05:37:33+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-3115", "CVE-2013-3143", "CVE-2013-3144", "CVE-2013-3145",
                "CVE-2013-3146", "CVE-2013-3147", "CVE-2013-3148", "CVE-2013-3149",
                "CVE-2013-3150", "CVE-2013-3151", "CVE-2013-3152", "CVE-2013-3153",
                "CVE-2013-3161", "CVE-2013-3162", "CVE-2013-3163", "CVE-2013-3164",
                "CVE-2013-3166", "CVE-2013-3846");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-28 13:40:22 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2013-07-10 08:34:28 +0530 (Wed, 10 Jul 2013)");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (2846071)");

  script_tag(name:"summary", value:"This host is missing a critical security update according to Microsoft
  Bulletin MS13-055.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"insight", value:"Multiple unspecified errors due to improper handling of the
  encoding for Shift_JIS auto-selection or of objects in memory.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 6.x/7.x/8.x/9.x/10.x.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to corrupt memory by the
  execution of arbitrary code in the context of the current user.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2846071");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60941");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60957");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60962");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60963");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60964");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60965");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60966");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60967");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60968");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60969");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60970");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60971");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60972");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60973");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60974");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60975");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60976");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-055");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/IE/Version");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win7:2, win2008:3, win8:1) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer || ieVer !~ "^([6-9]|10)\."){
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

if(hotfix_check_sp(xp:4) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.2900.6400") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.21341")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.23506")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win2003:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.3790.5170") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.21341")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.23506")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.18860")||
     version_in_range(version:dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.23132")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19442")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23506")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16495")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20605")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2) > 0)
{
  if(version_in_range(version:dllVer, test_version:"8.0.7601.16000", test_version2:"8.0.7601.18169")||
     version_in_range(version:dllVer, test_version:"8.0.7601.21000", test_version2:"8.0.7601.22340")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16495")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20605")||
     version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.16634")||
     version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.20741")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win8:1) > 0)
{
  if(version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.16634")||
     version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.20741")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
