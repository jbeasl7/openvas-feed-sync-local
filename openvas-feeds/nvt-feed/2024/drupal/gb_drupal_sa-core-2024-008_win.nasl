# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153508");
  script_version("2024-12-11T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-12-11 05:05:30 +0000 (Wed, 11 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-11-25 07:58:33 +0000 (Mon, 25 Nov 2024)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2024-55638");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal PHP Object Injection Vulnerability (SA-CORE-2024-008) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Drupal is prone to a PHP object injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Drupal core contains a potential PHP Object Injection
  vulnerability that (if combined with another exploit) could lead to remote code execution. It is
  not directly exploitable. This issue is mitigated by the fact that in order for it to be
  exploitable, a separate vulnerability must be present to allow an attacker to pass unsafe input
  to unserialize(). There are no such known exploits in Drupal core. To help protect against this
  potential vulnerability, some additional checks have been added to Drupal core's database code.
  If you use a third-party database driver, check the release notes for additional configuration
  steps that may be required in certain cases.");

  script_tag(name:"affected", value:"Drupal version 7.x through 7.101,  8.x through 10.2.10 and
  10.3.x through 10.3.8.");

  script_tag(name:"solution", value:"Update to version 7.102, 10.2.11, 10.3.9 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2024-008");

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

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.102")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.102", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0.0", test_version_up: "10.2.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.2.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.3.0", test_version_up: "10.3.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.3.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
