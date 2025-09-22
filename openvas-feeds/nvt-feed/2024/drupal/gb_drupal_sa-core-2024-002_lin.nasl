# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153226");
  script_version("2024-12-06T15:41:14+0000");
  script_tag(name:"last_modification", value:"2024-12-06 15:41:14 +0000 (Fri, 06 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-10-22 07:55:31 +0000 (Tue, 22 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");

  script_cve_id("CVE-2024-11942");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal Improper Error Handling Vulnerability (SA-CORE-2024-002) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Drupal is prone to an improper error handling vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Under certain uncommon site configurations, a bug in the
  CKEditor 5 module can cause some image uploads to move the entire webroot to a different location
  on the file system. This could be exploited by a malicious user to take down a site.");

  script_tag(name:"affected", value:"Drupal version 10.0.x prior to 10.2.10.");

  script_tag(name:"solution", value:"Update to version 10.2.10, or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2024-002");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.2.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.2.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
