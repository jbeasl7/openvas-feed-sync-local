# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108638");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-09-09 08:48:28 +0000 (Mon, 09 Sep 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP Multiple Vulnerabilities (Sep 2019) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"PHP is prone to multiple vulnerabilities:

  - Buffer overflow in zendparse

  - Cast to object confuses GC, causes crash

  - Exif crash (bus error) due to wrong alignment and invalid cast

  - Use-after-free in FPM master event handling");

  script_tag(name:"affected", value:"PHP versions before 7.2.22 and 7.3.x before 7.3.9.");

  script_tag(name:"solution", value:"Update to version 7.2.22, 7.3.9 or later.");

  script_xref(name:"URL", value:"http://bugs.php.net/78363");
  script_xref(name:"URL", value:"http://bugs.php.net/78379");
  script_xref(name:"URL", value:"http://bugs.php.net/78333");
  script_xref(name:"URL", value:"http://bugs.php.net/77185");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.3.9");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.2.22");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less(version: version, test_version: "7.2.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.22", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.3", test_version2: "7.3.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.9", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
