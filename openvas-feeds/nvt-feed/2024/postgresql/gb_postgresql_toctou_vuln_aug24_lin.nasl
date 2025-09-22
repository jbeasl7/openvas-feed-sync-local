# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152847");
  script_version("2025-05-09T15:42:11+0000");
  script_tag(name:"last_modification", value:"2025-05-09 15:42:11 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2024-08-09 02:42:27 +0000 (Fri, 09 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-12 15:54:52 +0000 (Mon, 12 Aug 2024)");

  script_cve_id("CVE-2024-7348");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL TOCTOU Vulnerability (Aug 2024) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_postgresql_consolidation.nasl",
                      "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PostgreSQL is prone to a time-of-check time-of-use (TOCTOU)
  race condition vulnerability in pg_dump.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Time-of-check Time-of-use (TOCTOU) race condition in pg_dump in
  allows an object creator to execute arbitrary SQL functions as the user running pg_dump, which is
  often a superuser. The attack involves replacing another relation type with a view or foreign
  table. The attack requires waiting for pg_dump to start, but winning the race condition is
  trivial if the attacker retains an open transaction.");

  script_tag(name:"affected", value:"PostgreSQL version 12.x prior to 12.20, 13.x prior to 13.16,
  14.x prior to 14.13, 15.x prior to 15.8 and 16.x prior to 16.4.");

  script_tag(name:"solution", value:"Update to version 12.20, 13.16, 14.13, 15.8, 16.4 or later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2024-7348/");
  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/postgresql-164-158-1413-1316-1220-and-17-beta-3-released-2910/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "12.0", test_version_up: "12.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "13.0", test_version_up: "13.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.0", test_version_up: "14.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "15.0", test_version_up: "15.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "16.0", test_version_up: "16.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
