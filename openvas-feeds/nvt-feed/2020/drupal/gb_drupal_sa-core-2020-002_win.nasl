# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144145");
  script_version("2025-01-31T15:39:24+0000");
  script_tag(name:"last_modification", value:"2025-01-31 15:39:24 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2020-06-19 05:30:03 +0000 (Fri, 19 Jun 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-11022", "CVE-2020-11023");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal 7.x, 8.x jQuery XSS Vulnerabilities (SA-CORE-2020-002) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Drupal is prone to multiple cross-site scripting vulnerabilities in jQuery.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The jQuery project released version 3.5.0, and as part of that, disclosed
  two security vulnerabilities that affect all prior versions. These vulnerabilities may be exploitable on some
  Drupal sites.");

  script_tag(name:"affected", value:"Drupal 7.x, 8.7.x and earlier and 8.8.x.");

  script_tag(name:"solution", value:"Update to version 7.70, 8.7.14, 8.8.6 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2020-002");

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

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.69")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.70", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.7.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.7.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.8", test_version2: "8.8.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.8.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
