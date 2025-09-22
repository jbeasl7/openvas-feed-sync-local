# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804376");
  script_version("2024-06-28T15:38:46+0000");
  script_cve_id("CVE-2007-5020", "CVE-2007-3896");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-04-10 10:20:46 +0530 (Thu, 10 Apr 2014)");
  script_name("Adobe Reader URI Handler Remote Code Execution Vulnerabilities (Oct 2007) - Windows");

  script_tag(name:"summary", value:"Adobe Reader is prone to remote code execution (RCE)
  vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaws are due to an input validation error when handling specially crafted
URIs with registered URI handlers.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code and
compromise a user's system.");
  script_tag(name:"affected", value:"Adobe Reader version 8.1 and prior on Windows.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 8.1.1 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/26201");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/25748");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/25945");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1018723");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1018822");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/36722");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb07-18.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("secpod_reg.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) <= 0) {
  exit(0);
}

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"8.1")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less than or equal to 8.1");
  security_message(port:0, data:report);
  exit(0);
}
