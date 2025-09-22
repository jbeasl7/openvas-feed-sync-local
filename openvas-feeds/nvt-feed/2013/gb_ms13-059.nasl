# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903315");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2013-3184", "CVE-2013-3186", "CVE-2013-3187", "CVE-2013-3188",
                "CVE-2013-3189", "CVE-2013-3190", "CVE-2013-3191", "CVE-2013-3192",
                "CVE-2013-3193", "CVE-2013-3194", "CVE-2013-3199");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-08-14 08:14:59 +0530 (Wed, 14 Aug 2013)");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (2862772)");

  script_tag(name:"summary", value:"This host is missing a critical security update according to Microsoft
  Bulletin MS13-059.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"insight", value:"Multiple flaws due to:

  - Error when handling process integrity level assignments and EUC-JP character
  encoding.

  - Multiple unspecified errors.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 6.x/7.x/8.x/9.x/10.x/11.x.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to corrupt memory by the execution of arbitrary code in the context of the current user.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-059");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61663");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61664");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61668");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61669");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61670");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61671");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61675");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61677");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61678");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61679");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61680");
  script_xref(name:"URL", value:"http://support.microsoft.com/default.aspx?scid=kb;EN-US;2862772");
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

if(hotfix_check_sp(xp:4) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.2900.6425") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.21347")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.23514")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win2003:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.3790.5198") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.21347")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.23514")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.18890")||
     version_in_range(version:dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.23163")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19452")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23514")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16501")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20612")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2) > 0)
{
  if(version_in_range(version:dllVer, test_version:"8.0.7601.16000", test_version2:"8.0.7601.18209")||
     version_in_range(version:dllVer, test_version:"8.0.7601.21000", test_version2:"8.0.7601.22388")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16501")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20612")||
     version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.16659")||
     version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.20767")||
     version_in_range(version:dllVer, test_version:"11.0.9431.000", test_version2:"11.0.9431.179")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win8:1) > 0)
{
  if(version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.16659")||
     version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.20767")||
     version_in_range(version:dllVer, test_version:"11.0.9431.000", test_version2:"11.0.9431.180")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
