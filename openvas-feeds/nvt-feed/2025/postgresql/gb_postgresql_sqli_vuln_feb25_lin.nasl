# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154018");
  script_version("2025-05-09T15:42:11+0000");
  script_tag(name:"last_modification", value:"2025-05-09 15:42:11 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2025-02-14 02:56:48 +0000 (Fri, 14 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-1094");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL SQLi Vulnerability (Feb 2025) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_postgresql_consolidation.nasl",
                      "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PostgreSQL is prone to an SQL injection (SQLi)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Improper neutralization of quoting syntax in PostgreSQL libpq
  functions PQescapeLiteral(), PQescapeIdentifier(), PQescapeString(), and PQescapeStringConn()
  allows a database input provider to achieve SQL injection in certain usage patterns.
  Specifically, SQL injection requires the application to use the function result to construct
  input to psql, the PostgreSQL interactive terminal. Similarly, improper neutralization of quoting
  syntax in PostgreSQL command line utility programs allows a source of command line arguments to
  achieve SQL injection when client_encoding is BIG5 and server_encoding is one of EUC_TW or
  MULE_INTERNAL.");

  script_tag(name:"affected", value:"PostgreSQL prior to version 13.19, 14.x prior to 14.16, 15.x
  prior to 15.11, 16.x prior to 16.7 and 17.x prior to 17.3.");

  script_tag(name:"solution", value:"Update to version 13.19, 14.16, 15.11, 16.7, 17.3 or later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2025-1094/");
  script_xref(name:"URL", value:"https://attackerkb.com/topics/G5s8ZWAbYH/cve-2024-12356/rapid7-analysis");
  script_xref(name:"URL", value:"https://www.rapid7.com/blog/post/2025/02/13/cve-2025-1094-postgresql-psql-sql-injection-fixed/");

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

if (version_is_less(version: version, test_version: "13.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.0", test_version_up: "14.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "15.0", test_version_up: "15.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "16.0", test_version_up: "16.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "17.0", test_version_up: "17.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
