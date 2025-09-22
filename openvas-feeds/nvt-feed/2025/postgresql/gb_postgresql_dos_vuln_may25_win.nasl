# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154471");
  script_version("2025-05-09T15:42:11+0000");
  script_tag(name:"last_modification", value:"2025-05-09 15:42:11 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-09 04:42:58 +0000 (Fri, 09 May 2025)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2025-4207");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL DoS Vulnerability (Feb 2025) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_postgresql_consolidation.nasl",
                      "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PostgreSQL is prone to a denial of service (DoS) vulnerability
  due to a buffer over-read.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A buffer over-read in PostgreSQL GB18030 encoding validation
  allows a database input provider to achieve temporary denial of service on platforms where a
  1-byte over-read can elicit process termination.");

  script_tag(name:"affected", value:"PostgreSQL prior to version 13.21, 14.x prior to 14.18, 15.x
  prior to 15.13, 16.x prior to 16.9 and 17.x prior to 17.5.");

  script_tag(name:"solution", value:"Update to version 13.21, 14.18, 15.13, 16.9, 17.5 or later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2025-4207/");
  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/postgresql-175-169-1513-1418-and-1321-released-3072/");

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

if (version_is_less(version: version, test_version: "13.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.0", test_version_up: "14.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive( version: version, test_version_lo: "15.0", test_version_up: "15.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive( version: version, test_version_lo: "16.0", test_version_up: "16.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive( version: version, test_version_lo: "17.0", test_version_up: "17.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
