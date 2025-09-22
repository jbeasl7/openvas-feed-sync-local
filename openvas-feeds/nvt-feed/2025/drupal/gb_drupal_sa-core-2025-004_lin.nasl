# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154219");
  script_version("2025-04-02T05:40:12+0000");
  script_tag(name:"last_modification", value:"2025-04-02 05:40:12 +0000 (Wed, 02 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-03-20 04:28:44 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2025-31675");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal XSS Vulnerability (SA-CORE-2025-004) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Drupal is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Drupal core Link field attributes are not sufficiently
  sanitized, which can lead to a cross-site scripting vulnerability (XSS).");

  script_tag(name:"affected", value:"Drupal version 8.x through 11.1.x.");

  script_tag(name:"solution", value:"Update to version 10.3.14, 10.4.5, 11.0.13, 11.1.5 or
  later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2025-004");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE,
                                          version_regex: "^[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "8.0.0", test_version_up: "10.3.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.3.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.4.0", test_version_up: "10.4.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0", test_version_up: "11.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.1.0", test_version_up: "11.1.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.1.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
