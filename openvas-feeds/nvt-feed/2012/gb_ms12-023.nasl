# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902670");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-0168", "CVE-2012-0169", "CVE-2012-0170", "CVE-2012-0171",
                "CVE-2012-0172");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-04-11 10:04:47 +0530 (Wed, 11 Apr 2012)");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (2675157)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2675157");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52889");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52902");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52904");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52905");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026901");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/48724");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-023");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to gain sensitive
  information or execute arbitrary code in the context of the application.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 6.x/7.x/8.x/9.x.");

  script_tag(name:"insight", value:"Multiple flaws are due to an:

  - Unspecified error in the Print feature.

  - Error in the handling of the onReadyStateChange event, VML styles
    and JScript9 when accessing already deleted.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-023.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer || ieVer !~ "^[6-9]\."){
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
  if(version_in_range(version:dllVer, test_version:"6.0.2900.0000", test_version2:"6.0.2900.6196") ||
     version_in_range(version:dllVer, test_version:"7.0.0000.00000", test_version2:"7.0.6000.17108")||
     version_in_range(version:dllVer, test_version:"7.0.6000.21000", test_version2:"7.0.6000.21310")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19221")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23317")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win2003:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"6.0.3790.0000", test_version2:"6.0.3790.4968") ||
     version_in_range(version:dllVer, test_version:"7.0.0000.00000", test_version2:"7.0.6000.17108")||
     version_in_range(version:dllVer, test_version:"7.0.6000.21000", test_version2:"7.0.6000.21310")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19221")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23317")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.18590")||
     version_in_range(version:dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.22804")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19221")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23317")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16442")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20547")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2) > 0)
{
  if(version_in_range(version:dllVer, test_version:"8.0.7600.16000", test_version2:"8.0.7600.16967")||
     version_in_range(version:dllVer, test_version:"8.0.7600.20000", test_version2:"8.0.7600.21157")||
     version_in_range(version:dllVer, test_version:"8.0.7601.16000", test_version2:"8.0.7601.17784")||
     version_in_range(version:dllVer, test_version:"8.0.7601.21000", test_version2:"8.0.7601.21930")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16442")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20547")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
