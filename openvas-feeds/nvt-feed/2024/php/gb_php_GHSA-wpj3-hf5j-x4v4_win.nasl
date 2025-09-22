# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152121");
  script_version("2025-04-30T05:39:51+0000");
  script_tag(name:"last_modification", value:"2025-04-30 05:39:51 +0000 (Wed, 30 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-04-15 05:07:01 +0000 (Mon, 15 Apr 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");

  script_cve_id("CVE-2024-2756");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 8.1.11 < 8.1.28, 8.2.x < 8.2.18, 8.3.x < 8.3.6 Security Update (GHSA-wpj3-hf5j-x4v4) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to a __Host-/__Secure- cookie bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to an incomplete fix to CVE-2022-31629, network and
  same-site attackers can set a standard insecure cookie in the victim's browser which is treated
  as a __Host- or __Secure- cookie by PHP applications.");

  script_tag(name:"affected", value:"PHP version 8.1.11 through 8.1.27, version 8.2.x through
  8.2.17 and 8.3.x through 8.3.5.");

  script_tag(name:"solution", value:"Update to version 8.1.28, 8.2.18, 8.3.6 or later.");

  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-wpj3-hf5j-x4v4");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.1.28");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.2.18");
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

if (version_in_range_exclusive(version: version, test_version_lo: "8.1.11", test_version_up: "8.1.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.28", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.2", test_version_up: "8.2.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.3", test_version_up: "8.3.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.3.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
