# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154187");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-03-14 03:00:15 +0000 (Fri, 14 Mar 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-02 20:17:38 +0000 (Wed, 02 Jul 2025)");

  script_cve_id("CVE-2025-1217", "CVE-2025-1219", "CVE-2025-1734", "CVE-2025-1736",
                "CVE-2025-1861");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 8.1.32, 8.2.x < 8.2.28 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_php_ssh_login_detect.nasl",
                      "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-1217: Header parser of 'http' stream wrapper does not handle folded headers

  - CVE-2025-1219: libxml streams use wrong 'content-type' header when requesting a redirected
  resource

  - CVE-2025-1734: Streams HTTP wrapper does not fail for headers without colon

  - CVE-2025-1736: Stream HTTP wrapper header check might omit basic auth header

  - CVE-2025-1861: Stream HTTP wrapper truncate redirect location to 1024 bytes");

  script_tag(name:"affected", value:"PHP versions prior to 8.1.32, and 8.2.x prior to 8.2.28.");

  script_tag(name:"solution", value:"Update to version 8.1.32, 8.2.28 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.1.32");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.2.28");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-v8xr-gpvj-cx9g");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-p3x9-6h7p-cgfc");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-pcmh-g36c-qc44");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-hgf5-96fm-v528");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-52jp-hrpf-2jff");

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

if (version_is_less(version: version, test_version: "8.1.32")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.2", test_version_up: "8.2.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.28", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
