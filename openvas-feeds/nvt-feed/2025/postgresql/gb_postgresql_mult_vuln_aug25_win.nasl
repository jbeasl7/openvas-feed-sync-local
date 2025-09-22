# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155169");
  script_version("2025-08-20T05:40:05+0000");
  script_tag(name:"last_modification", value:"2025-08-20 05:40:05 +0000 (Wed, 20 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-19 03:06:08 +0000 (Tue, 19 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-8713", "CVE-2025-8714", "CVE-2025-8715");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL Multiple Vulnerabilities (Aug 2025) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_postgresql_consolidation.nasl",
                      "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PostgreSQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-8713: Optimizer statistics can expose sampled data within a view, partition, or child
  table

  - CVE-2025-8714: pg_dump lets superuser of origin server execute arbitrary code in psql client

  - CVE-2025-8715: pg_dump newline in object name executes arbitrary code in psql client and in
  restore target server");

  script_tag(name:"affected", value:"PostgreSQL prior to version 13.22, 14.x prior to 14.19, 15.x
  prior to 15.14, 16.x prior to 16.10 and 17.x prior to 17.6.");

  script_tag(name:"solution", value:"Update to version 13.22, 14.19, 15.14, 16.10, 17.6 or
  later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/postgresql-176-1610-1514-1419-1322-and-18-beta-3-released-3118/");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2025-8713/");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2025-8714/");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2025-8715/");

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

if (version_is_less(version: version, test_version: "13.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.0", test_version_up: "14.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "15.0", test_version_up: "15.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "16.0", test_version_up: "16.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "17.0", test_version_up: "17.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
