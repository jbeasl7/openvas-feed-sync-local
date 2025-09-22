# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142696");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-08-05 08:29:51 +0000 (Mon, 05 Aug 2019)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-02 15:05:00 +0000 (Fri, 02 Oct 2020)");

  script_cve_id("CVE-2019-11041", "CVE-2019-11042");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP Multiple Vulnerabilities (Aug 2019) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple heap-based buffer overflows vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"PHP is prone to multiple vulnerabilities:

  - Heap-buffer-overflow on exif_scan_thumbnail (CVE-2019-11041)

  - Heap-buffer-overflow on exif_process_user_comment (CVE-2019-11042)");

  script_tag(name:"affected", value:"PHP version 7.x before 7.1.31, 7.2.x before 7.2.21 and 7.3.x before 7.3.8.");

  script_tag(name:"solution", value:"Update to version 7.1.31, 7.2.21, 7.3.8 or later.");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=78256");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=78222");

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

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.1.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.31", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.2", test_version2: "7.2.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.21", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.3", test_version2: "7.3.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.8", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
