# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804390");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2006-3093");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-04-11 13:14:20 +0530 (Fri, 11 Apr 2014)");
  script_name("Adobe Reader Multiple Unspecified Vulnerabilities (Jun 2006) - Windows");

  script_tag(name:"summary", value:"Adobe Reader is prone to multiple unspecified vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaws exist due to some unspecified errors.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to have unspecified impact.");
  script_tag(name:"affected", value:"Adobe Reader before version 7.0.8 on Windows.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 7.0.8 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/20576");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/18445");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1016314");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/31829");
  script_xref(name:"URL", value:"http://www.adobe.com/support/techdocs/327817.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"7.0.8")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.0.8");
  security_message(port:0, data:report);
  exit(0);
}
