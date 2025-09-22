# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154052");
  script_version("2025-04-02T05:40:12+0000");
  script_tag(name:"last_modification", value:"2025-04-02 05:40:12 +0000 (Wed, 02 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-02-20 04:39:57 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2025-3057", "CVE-2025-31673", "CVE-2025-31674");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal Multiple Vulnerabilities (SA-CORE-2025-001, SA-CORE-2025-002, SA-CORE-2025-003) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Drupal is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-3057 / SA-CORE-2025-001: Cross-site scripting (XSS)

  - CVE-2025-31673 / SA-CORE-2025-002: Access bypass

  - CVE-2025-31674 / SA-CORE-2025-003: Gadget chain");

  script_tag(name:"affected", value:"Drupal version 8.x through 11.1.x.");

  script_tag(name:"solution", value:"Update to version 10.3.13, 10.4.3, 11.0.12, 11.1.3 or
  later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2025-001");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2025-002");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2025-003");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.0.0", test_version_up: "10.3.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.3.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.4.0", test_version_up: "10.4.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0", test_version_up: "11.0.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.1.0", test_version_up: "11.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.1.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
