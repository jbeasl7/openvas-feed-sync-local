# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mariadb:mariadb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145119");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-01-12 08:39:57 +0000 (Tue, 12 Jan 2021)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-30 18:09:00 +0000 (Wed, 30 Dec 2020)");

  script_cve_id("CVE-2020-28912");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MariaDB Named Pipe Permission Vulnerability (MDEV-24040) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mariadb/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"MariaDB is prone to a named pipe permission vulnerability.");

  script_tag(name:"insight", value:"With MariaDB running on Windows, when local clients connect to the server
  over named pipes, it's possible for an unprivileged user with an ability to run code on the server machine
  to intercept the named pipe connection and act as a man-in-the-middle, gaining access to all the data passed
  between the client and the server, and getting the ability to run SQL commands on behalf of the connected
  user. This occurs because of an incorrect security descriptor.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"MariaDB versions 10.1, 10.2, 10.3, 10.4 and 10.5.");

  script_tag(name:"solution", value:"Update to version 10.1.48, 10.2.35, 10.3.26, 10.4.16, 10.5.7 or later.");

  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-24040");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "10.1.0", test_version2: "10.1.47")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.48");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.2.0", test_version2: "10.2.34")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.2.35");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.3.0", test_version2: "10.3.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.3.26");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.4.0", test_version2: "10.4.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.16");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.5.0", test_version2: "10.5.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
