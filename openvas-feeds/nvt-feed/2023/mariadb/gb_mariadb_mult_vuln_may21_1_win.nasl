# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mariadb:mariadb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149348");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2023-02-22 04:15:10 +0000 (Wed, 22 Feb 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-26 12:15:00 +0000 (Wed, 26 May 2021)");

  script_cve_id("CVE-2021-2166", "CVE-2021-2154", "CVE-2022-21451");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MariaDB 10.3.x < 10.3.29, 10.4.x < 10.4.19, 10.5.x < 10.5.10 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mariadb/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"MariaDB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-2166: Denial of service (DoS) in MySQL

  - CVE-2021-2154: Denial of service (DoS) in MySQL

  - CVE-2022-21451: Denial of service (DoS) in MySQL");

  script_tag(name:"affected", value:"MariaDB version 10.3.x prior to 10.3.29, 10.4.x prior to
  10.4.19 and 10.5.x prior to 10.5.10.");

  script_tag(name:"solution", value:"Update to version 10.3.29, 10.4.19, 10.5.10 or later.");

  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10329-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10419-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10510-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/security/#full-list-of-cves-fixed-in-mariadb");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "10.3.0", test_version_up: "10.3.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.3.29");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.4.0", test_version_up: "10.4.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.19");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.5.0", test_version_up: "10.5.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.10");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
