# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154951");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-07-16 04:11:16 +0000 (Wed, 16 Jul 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-15 20:15:44 +0000 (Tue, 15 Jul 2025)");

  script_cve_id("CVE-2025-50078", "CVE-2025-50082", "CVE-2025-50083", "CVE-2025-50085",
                "CVE-2025-50077", "CVE-2025-50092", "CVE-2025-50099", "CVE-2025-50086",
                "CVE-2025-50093", "CVE-2025-50079", "CVE-2025-50084", "CVE-2025-50087",
                "CVE-2025-50091", "CVE-2025-50101", "CVE-2025-50102", "CVE-2025-50097",
                "CVE-2025-50080", "CVE-2025-50096", "CVE-2025-5399", "CVE-2025-50104",
                "CVE-2025-50098", "CVE-2025-50100");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL Server 8.0.0 - 8.0.42, 8.4.0 - 8.4.5, 9.0.0 - 9.3.0 Security Update (cpujul2025) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL Server version 8.0.0 through 8.0.42, 8.4.0
  through 8.4.5 and 9.0.0 through 9.3.0.");

  script_tag(name:"solution", value:"Update to version 8.0.43, 8.4.6, 9.3.1 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2025.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpujul2025");

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

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.0.42")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.43", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.4.0", test_version2: "8.4.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.4.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0.0", test_version2: "9.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
