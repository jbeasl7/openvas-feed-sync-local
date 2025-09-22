# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152122");
  script_version("2024-04-16T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-04-16 05:05:31 +0000 (Tue, 16 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-04-15 05:09:36 +0000 (Mon, 15 Apr 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2024-2757");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 8.3.x < 8.3.6 DoS Vulnerability (GHSA-fjp9-9hwx-59fq) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Certain inputs provided to mb_encode_mimeheader trigger an
  endless loop.");

  script_tag(name:"impact", value:"Given that this function is integral to numerous email
  processing routines, including those handling potentially untrusted user inputs, this
  vulnerability could be exploited for denial of service attacks. For instance, CakePHP 5 relies on
  this function to encode email subjects.");

  script_tag(name:"affected", value:"PHP version 8.3.x through 8.3.5.");

  script_tag(name:"solution", value:"Update to version 8.3.6 or later.");

  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-fjp9-9hwx-59fq");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.3.6");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.3", test_version_up: "8.3.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.3.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
