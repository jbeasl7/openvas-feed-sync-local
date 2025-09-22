# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903336");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2014-0267", "CVE-2014-0268", "CVE-2014-0269", "CVE-2014-0270",
                "CVE-2014-0271", "CVE-2014-0272", "CVE-2014-0273", "CVE-2014-0274",
                "CVE-2014-0275", "CVE-2014-0276", "CVE-2014-0277", "CVE-2014-0278",
                "CVE-2014-0279", "CVE-2014-0280", "CVE-2014-0281", "CVE-2014-0283",
                "CVE-2014-0284", "CVE-2014-0285", "CVE-2014-0286", "CVE-2014-0287",
                "CVE-2014-0288", "CVE-2014-0289", "CVE-2014-0290", "CVE-2014-0293");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2014-02-12 08:09:41 +0530 (Wed, 12 Feb 2014)");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (2909921)");

  script_tag(name:"summary", value:"This host is missing a critical security update according to Microsoft
  Bulletin MS14-010.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An unspecified error exists during validation of local file installation
  and secure creation of registry keys.

  - An error within the VBScript engine.

  - Multiple unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to corrupt memory by the
  execution of arbitrary code, bypass certain security restrictions and compromise a user's system.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 6.x/7.x/8.x/9.x/10.x/11.x.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2909921");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65361");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65363");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65367");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65370");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65371");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65372");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65373");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65375");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65376");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65377");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65378");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65380");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65381");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65382");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65383");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65384");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65385");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65386");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65388");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65389");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65390");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65392");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65394");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65395");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms14-010");
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
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win7:2, win2008:3, win8:1, win8_1:1) <= 0){
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

if(hotfix_check_sp(xp:4) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.2900.6498") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.21365")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.23561")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win2003:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.3790.5281") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.21365")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.23561")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.19015")||
     version_in_range(version:dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.23302")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19498")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23561")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16532")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20643")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2) > 0)
{
  if(version_in_range(version:dllVer, test_version:"8.0.7601.16000", test_version2:"8.0.7601.18364")||
     version_in_range(version:dllVer, test_version:"8.0.7601.21000", test_version2:"8.0.7601.22566")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16532")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20643")||
     version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.16797")||
     version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.20915")||
     version_in_range(version:dllVer, test_version:"11.0.9600.16000", test_version2:"11.0.9600.16517")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win8:1) > 0)
{
  if(version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.16797")||
     version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.20915")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win8_1:1) > 0)
{
  if(version_in_range(version:dllVer, test_version:"11.0.9600.16000", test_version2:"11.0.9600.16517")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
