# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142158");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-03-22 15:39:40 +0100 (Fri, 22 Mar 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-16 02:29:00 +0000 (Thu, 16 May 2019)");

  script_cve_id("CVE-2019-6341");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal XSS Vulnerability (SA-CORE-2019-004) - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Under certain circumstances the File module/subsystem allows a malicious user
to upload a file that can trigger a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Drupal 7, 8.5.x and 8.6.x.");

  script_tag(name:"solution", value:"Update to version 7.65, 8.5.14, 8.6.13 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2019-004");

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

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.64")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.65", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.5.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.6", test_version2: "8.6.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.6.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
