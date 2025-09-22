# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mariadb:mariadb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146395");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-07-29 06:49:34 +0000 (Thu, 29 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-26 16:30:00 +0000 (Mon, 26 Jul 2021)");

  script_cve_id("CVE-2021-2372", "CVE-2021-2389");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MariaDB Multiple Vulnerabilities (Jul 2021) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mariadb/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"MariaDB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-2372: Difficult to exploit vulnerability allows high privileged attacker with network
  access via multiple protocols to compromise the MariaDB server.

  - CVE-2021-2389: Difficult to exploit vulnerability allows unauthenticated attacker with network
  access via multiple protocols to compromise the MariaDB server.");

  script_tag(name:"affected", value:"MariaDB versions 10.2.x, 10.3.x, 10.4.x, 10.5.x and 10.6.x.");

  script_tag(name:"solution", value:"Update to version 10.2.40, 10.3.31, 10.4.21, 10.5.12, 10.6.4
  or later.");

  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10240-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10331-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10421-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10512-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-1064-release-notes/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "10.2.0", test_version2: "10.2.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.2.40");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.3.0", test_version2: "10.3.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.3.31");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.4.0", test_version2: "10.4.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.21");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.5.0", test_version2: "10.5.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.12");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.6.0", test_version2: "10.6.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.6.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
