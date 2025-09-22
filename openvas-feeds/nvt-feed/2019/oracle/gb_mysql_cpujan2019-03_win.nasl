# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112493");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-01-16 13:12:11 +0100 (Wed, 16 Jan 2019)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-31 17:40:00 +0000 (Tue, 31 Jan 2023)");

  script_cve_id("CVE-2019-2533", "CVE-2019-2436", "CVE-2019-2536", "CVE-2019-2502", "CVE-2019-2539",
                "CVE-2019-2494", "CVE-2019-2495", "CVE-2019-2530", "CVE-2019-2535", "CVE-2019-2513");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL Server 8.0 <= 8.0.13 Security Update (cpujan2019) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The attacks range in variety and difficulty. Most of them allow an attacker
  with network access via multiple protocols to compromise the MySQL Server.

  For further information refer to the official advisory via the referenced link.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability can result in unauthorized
  access to critical data or complete access to all MySQL Server accessible data and unauthorized ability
  to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL Server versions 8.0 through 8.0.13.");

  script_tag(name:"solution", value:"Updates are available. Apply the necessary patch from the referenced link.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujan2019.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpujan2019");

  exit(0);
}

CPE = "cpe:/a:oracle:mysql";

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version: vers, test_version: "8.0", test_version2: "8.0.13")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "Apply the patch", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
