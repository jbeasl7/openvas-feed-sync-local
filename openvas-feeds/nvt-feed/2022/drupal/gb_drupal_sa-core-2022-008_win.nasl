# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148040");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2022-05-03 09:34:18 +0000 (Tue, 03 May 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-09 18:47:00 +0000 (Tue, 09 May 2023)");

  script_cve_id("CVE-2022-25273");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal Input Validation Vulnerability (SA-CORE-2022-008) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Drupal is prone to an improper input validation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Drupal core's form API has a vulnerability where certain
  contributed or custom modules' forms may be vulnerable to improper input validation. This could
  allow an attacker to inject disallowed values or overwrite data.");

  script_tag(name:"affected", value:"Drupal version 9.x.");

  script_tag(name:"solution", value:"Update to version 9.2.18, 9.3.12 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2022-008");

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

if (version_in_range_exclusive(version: version, test_version_lo: "9.0", test_version_up: "9.2.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.3", test_version_up: "9.3.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
