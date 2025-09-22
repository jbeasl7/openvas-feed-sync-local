# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153446");
  script_version("2025-05-09T15:42:11+0000");
  script_tag(name:"last_modification", value:"2025-05-09 15:42:11 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2024-11-15 09:48:12 +0000 (Fri, 15 Nov 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-11 21:27:49 +0000 (Tue, 11 Feb 2025)");

  script_cve_id("CVE-2024-10976", "CVE-2024-10977", "CVE-2024-10978", "CVE-2024-10979");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL Multiple Vulnerabilities (Nov 2024) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_postgresql_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PostgreSQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-10976: Row security below e.g. subqueries disregards user ID changes

  - CVE-2024-10977: libpq retains an error message from man-in-the-middle

  - CVE-2024-10978: SET ROLE, SET SESSION AUTHORIZATION reset to wrong user ID

  - CVE-2024-10979: PL/Perl environment variable changes execute arbitrary code");

  script_tag(name:"affected", value:"PostgreSQL version 12.x prior to 12.21, 13.x prior to 13.17,
  14.x prior to 14.14, 15.x prior to 15.9, 16.x prior to 16.5 and 17.x prior to 17.1.");

  script_tag(name:"solution", value:"Update to version 12.21, 13.17, 14.14, 15.9, 16.5, 17.1 or
  later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/postgresql-171-165-159-1414-1317-and-1221-released-2955/");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2024-10976/");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2024-10977/");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2024-10978/");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2024-10979/");
  script_xref(name:"URL", value:"https://www.varonis.com/blog/cve-postgresql-pl/perl");

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

if (version_in_range_exclusive(version: version, test_version_lo: "12.0", test_version_up: "12.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "13.0", test_version_up: "13.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.0", test_version_up: "14.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "15.0", test_version_up: "15.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "16.0", test_version_up: "16.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "17.0", test_version_up: "17.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
