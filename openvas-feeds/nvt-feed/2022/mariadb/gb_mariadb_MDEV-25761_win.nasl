# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mariadb:mariadb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147572");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2022-02-02 05:02:00 +0000 (Wed, 02 Feb 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-07 21:09:00 +0000 (Mon, 07 Mar 2022)");

  script_cve_id("CVE-2021-46664");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MariaDB DoS Vulnerability (MDEV-25761) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mariadb/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"MariaDB is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MariaDB allows an application crash in sub_select_postjoin_aggr
  for a NULL value of aggr.");

  script_tag(name:"affected", value:"MariaDB versions prior to 10.2.43, 10.3.x prior to 10.3.34,
  10.4.x prior to 10.4.24, 10.5.x prior to 10.5.15, 10.6.x prior to 10.6.7 and 10.7.x prior to
  10.7.3.");

  script_tag(name:"solution", value:"Update to version 10.2.43, 10.3.34, 10.4.24, 10.5.15, 10.6.7,
  10.7.3 or later.");

  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-25761");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/security/#full-list-of-cves-fixed-in-mariadb");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "10.2.43")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.2.43");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.3.0", test_version_up: "10.3.34")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.3.34");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.4.0", test_version_up: "10.4.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.24");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.5.0", test_version_up: "10.5.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.15");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.6.0", test_version_up: "10.6.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.6.7");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.7.0", test_version_up: "10.7.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.7.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
