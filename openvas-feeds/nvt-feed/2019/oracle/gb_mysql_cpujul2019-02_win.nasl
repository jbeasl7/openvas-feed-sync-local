# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142645");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-07-23 10:21:08 +0000 (Tue, 23 Jul 2019)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-30 18:31:00 +0000 (Mon, 30 Jan 2023)");

  script_cve_id("CVE-2019-2805", "CVE-2019-2740", "CVE-2019-2819", "CVE-2019-2739", "CVE-2019-2737",
                "CVE-2019-2738");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL Server <= 5.6.44 / 5.7 <= 5.7.26 / 8.0 <= 8.0.16 Security Update (cpujul2019) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Oracle MySQL Server is prone to multiple denial of service vulnerabilities.

  For further information refer to the official advisory via the referenced link.");

  script_tag(name:"affected", value:"Oracle MySQL Server versions 5.6.44 and prior, 5.7 through 5.7.26 and 8.0 through 8.0.16.");

  script_tag(name:"solution", value:"Update to version 5.6.45, 5.7.27, 8.0.17 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2019.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpujul2019");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less_equal(version: version, test_version: "5.6.44")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.45", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.7", test_version2: "5.7.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.27", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.17", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
