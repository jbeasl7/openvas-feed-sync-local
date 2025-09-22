# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804264");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2007-0103");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-04-16 12:27:12 +0530 (Wed, 16 Apr 2014)");
  script_name("Adobe Reader Multiple Vulnerabilities (Aug 2007) - Windows");

  script_tag(name:"summary", value:"Adobe Reader is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw exists due to unspecified error within Adobe PDF specification.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to conduct denial of service,
memory corruption and execution of arbitrary code.");
  script_tag(name:"affected", value:"Adobe Reader before version 8.0 on Windows.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader 8.0 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/31364");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21910");
  script_xref(name:"URL", value:"http://projects.info-pull.com/moab/MOAB-06-01-2007.html");
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

if(version_is_less(version:vers, test_version:"8.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.0");
  security_message(port:0, data:report);
  exit(0);
}
