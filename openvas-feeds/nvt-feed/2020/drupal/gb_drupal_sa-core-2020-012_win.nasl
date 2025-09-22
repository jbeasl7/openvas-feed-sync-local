# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117053");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2020-11-20 07:40:39 +0000 (Fri, 20 Nov 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-15 04:15:00 +0000 (Tue, 15 Dec 2020)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-13671");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal 7.x, 8.x, 9.x RCE Vulnerability (SA-CORE-2020-012) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Drupal is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Drupal core does not properly sanitize certain filenames on uploaded
  files, which can lead to files being interpreted as the incorrect extension and served as the wrong
  MIME type or executed as PHP for certain hosting configurations.");

  script_tag(name:"affected", value:"Drupal 7.x, 8.8.x and prior, 8.9.x and 9.0.x.");

  script_tag(name:"solution", value:"Update to version 7.74, 8.8.11, 8.9.9, 9.0.8 or later.

  Additionally, it's recommended that you audit all previously uploaded files to check for malicious extensions.
  Look specifically for files that include more than one extension, like filename.php.txt or filename.html.gif,
  without an underscore (_) in the extension. Pay specific attention to the following file extensions, which
  should be considered dangerous even when followed by one or more additional extensions:

  - phar

  - php

  - pl

  - py

  - cgi

  - asp

  - js

  - html

  - htm

  - phtml

  This list is not exhaustive, so evaluate security concerns for other unmunged extensions on a case-by-case basis.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2020-012");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "7.74")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.74", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.8.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.8.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.9", test_version2: "8.9.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.9.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0", test_version2: "9.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
