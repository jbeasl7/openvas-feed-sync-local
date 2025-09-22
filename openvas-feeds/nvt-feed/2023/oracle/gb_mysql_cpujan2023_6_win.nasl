# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149178");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2023-01-19 07:06:58 +0000 (Thu, 19 Jan 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-18 00:15:00 +0000 (Wed, 18 Jan 2023)");

  script_cve_id("CVE-2023-21868", "CVE-2023-21875", "CVE-2023-21869", "CVE-2023-21877",
                "CVE-2023-21880", "CVE-2023-21871", "CVE-2023-21836", "CVE-2023-21887",
                "CVE-2023-21863", "CVE-2023-21867", "CVE-2023-21870", "CVE-2023-21873",
                "CVE-2023-21876", "CVE-2023-21878", "CVE-2023-21879", "CVE-2023-21881",
                "CVE-2023-21883", "CVE-2023-21882");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL Server 8.x <= 8.0.31 Security Update (cpujan2023) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL Server version 8.0 through 8.0.31.");

  script_tag(name:"solution", value:"Update to version 8.0.32 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujan2023.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpujan2023");

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

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
