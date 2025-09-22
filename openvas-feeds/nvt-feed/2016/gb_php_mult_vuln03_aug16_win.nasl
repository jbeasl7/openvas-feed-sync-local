# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808791");
  script_version("2025-05-09T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-05-09 05:40:06 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2016-08-17 12:42:53 +0530 (Wed, 17 Aug 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_cve_id("CVE-2016-5094", "CVE-2016-5095", "CVE-2016-5096");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.5.36, 5.6.x < 5.6.22 Multiple Vulnerabilities (Aug 2016) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Integer overflow in the fread function in 'ext/standard/file.c' script.

  - Integer overflow in the php_html_entities function in 'ext/standard/html.c' script.

  - An Integer overflow in the php_escape_html_entities_ex function in 'ext/standard/html.c'
  script.");

  script_tag(name:"impact", value:"Successfully exploiting these issues allow remote attackers to
  cause a denial of service or possibly have unspecified other impact.");

  script_tag(name:"affected", value:"PHP prior to version 5.5.36 and 5.6.x prior to 5.6.22 on
  Windows.");

  script_tag(name:"solution", value:"Update to version 5.5.36, 5.6.22 or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90861");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90857");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92144");

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

if (version_is_less(version: version, test_version: "5.5.36")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.36", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.6.0", test_version_up: "5.6.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
