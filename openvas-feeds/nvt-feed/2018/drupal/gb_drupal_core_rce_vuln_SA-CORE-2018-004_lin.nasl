# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141028");
  script_version("2025-03-18T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-03-18 05:38:50 +0000 (Tue, 18 Mar 2025)");
  script_tag(name:"creation_date", value:"2018-04-26 08:47:32 +0700 (Thu, 26 Apr 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-20 12:52:00 +0000 (Tue, 20 Apr 2021)");

  script_cve_id("CVE-2018-7602");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal Core Critical RCE Vulnerability (SA-CORE-2018-004) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Drupal is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A remote code execution vulnerability exists within multiple
  subsystems of Drupal 7.x and 8.x. This potentially allows attackers to exploit multiple attack
  vectors on a Drupal site, which could result in the site being compromised. This vulnerability is
  related to SA-CORE-2018-002 (CVE-2018-7600).");

  script_tag(name:"affected", value:"Drupal 7.x and 8.x are known to be affected.");

  script_tag(name:"solution", value:"Update to version 7.59, 8.4.8, 8.5.3 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2018-004");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, version_regex:"^[0-9]\.[0-9.]+", exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.58")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.59", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.4.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.4.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.5", test_version2: "8.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
