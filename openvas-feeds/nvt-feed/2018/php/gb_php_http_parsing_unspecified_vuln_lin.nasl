# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813904");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-08-07 13:29:04 +0530 (Tue, 07 Aug 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-19 11:15:00 +0000 (Mon, 19 Aug 2019)");

  script_cve_id("CVE-2018-14884");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 7.x < 7.0.27, 7.1.x < 7.1.13, 7.2.0 Unspecified Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an inappropriate parsing of HTTP
  response 'http_header_value' in 'ext/standard/http_fopen_wrapper.c'.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause
  segmentation fault.");

  script_tag(name:"affected", value:"PHP versions 7.0.x prior to 7.0.27, 7.1.x prior to 7.1.13 and
  7.2.x prior to 7.2.1 on Linux.");

  script_tag(name:"solution", value:"Update to version 7.0.27, 7.1.13, 7.2.1 or later.");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=75535");

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

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.0.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.27", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.1.0", test_version_up: "7.1.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "7.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
