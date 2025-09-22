# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803994");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2011-3583");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-05 16:21:00 +0000 (Thu, 05 Dec 2019)");
  script_tag(name:"creation_date", value:"2013-12-31 16:02:00 +0530 (Tue, 31 Dec 2013)");
  script_name("TYPO3 Unspecified SQL Injection Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute SQL commands in
backend database.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An error exists in Database API, which fails to properly replace parameter
values.");
  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.5.6 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"TYPO3 is prone to an SQL injection (SQLi) vulnerability.");
  script_tag(name:"affected", value:"TYPO3 versions 4.5.0 to 4.5.5");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45940/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49628");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2011-002/");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_mandatory_keys("typo3/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"[0-9]+\.[0-9]+\.[0-9]+")) # nb: Version might not be exact enough
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"4.5.0", test_version2:"4.5.5")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"4.5.0 - 4.5.5", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
