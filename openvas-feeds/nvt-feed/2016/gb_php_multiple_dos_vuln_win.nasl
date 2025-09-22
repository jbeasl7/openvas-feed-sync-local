# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808610");
  script_version("2025-05-09T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-05-09 05:40:06 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2016-07-14 12:14:00 +0530 (Thu, 14 Jul 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 20:43:00 +0000 (Mon, 29 Aug 2022)");

  script_cve_id("CVE-2015-8874", "CVE-2015-8877", "CVE-2015-8879");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.6.12 Multiple DoS Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Improper handling of driver behavior for SQL_WVARCHAR columns in the 'odbc_bindcols function' in
  'ext/odbc/php_odbc.c' script.

  - The 'gdImageScaleTwoPass' function in gd_interpolation.c script in the GD Graphics Library uses
  inconsistent allocate and free approaches.");

  script_tag(name:"impact", value:"Successfully exploiting these issues allow remote attackers to
  cause a denial of service (application crash or memory consuption).");

  script_tag(name:"affected", value:"PHP prior to version 5.6.12 on Windows.");

  script_tag(name:"solution", value:"Update to version 5.6.12 or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90866");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90842");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90714");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.6.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
