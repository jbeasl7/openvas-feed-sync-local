# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153840");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-01-22 03:56:53 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-27 17:47:30 +0000 (Tue, 27 Aug 2024)");

  # nb: From the linked advisory:
  # > The patch for CVE-2024-37371 also addresses CVE-2024-37370.
  script_cve_id("CVE-2024-37371", "CVE-2025-21521", "CVE-2025-21525", "CVE-2025-21504",
                "CVE-2025-21536", "CVE-2025-21534", "CVE-2025-21494", "CVE-2024-37370");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL Server 8.0 - 8.0.39, 8.4 - 8.4.2, 9.0 - 9.0.1 Security Update (cpujan2025) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL Server version 8.0 through 8.0.39, 8.4 through
  8.4.2 and 9.0 through 9.0.1.");

  script_tag(name:"solution", value:"Update to version 8.0.40, 8.4.3, 9.0.2 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujan2025.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpujan2025");

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

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.40", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.4", test_version2: "8.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.4.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0", test_version2: "9.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
