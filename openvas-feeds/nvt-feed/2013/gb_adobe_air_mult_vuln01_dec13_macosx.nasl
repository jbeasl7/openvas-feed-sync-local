# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
CPE = "cpe:/a:adobe:adobe_air";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804171");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2013-5331", "CVE-2013-5332");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-12-18 17:07:12 +0530 (Wed, 18 Dec 2013)");
  script_name("Adobe AIR Multiple Vulnerabilities-01 (Dec 2013) - Mac OS X");


  script_tag(name:"summary", value:"Adobe Air is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to Adobe AIR version 3.9.0.1380 or later.");
  script_tag(name:"insight", value:"Flaws are due to multiple unspecified errors.");
  script_tag(name:"affected", value:"Adobe AIR before version 3.9.0.1380 on Mac OS X.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code, cause
memory corruption(denial of service) and compromise a user's system.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55948");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64199");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64201");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb13-28.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"3.9.0.1380")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.9.0.1380");
  security_message(port: 0, data: report);
  exit(0);
}
