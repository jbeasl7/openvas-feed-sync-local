# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117686");
  script_version("2024-07-19T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-07-19 05:05:32 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2021-09-20 08:33:39 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 20:58:00 +0000 (Thu, 10 Mar 2022)");

  script_cve_id("CVE-2021-3677");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL 11.x < 11.13, 12.x < 12.8, 13.x < 13.4 Memory Disclosure Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_postgresql_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PostgreSQL is prone to a memory disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A purpose-crafted query can read arbitrary bytes of server
  memory. In the default configuration, any authenticated database user can complete this attack at
  will. The attack does not require the ability to create objects. If server settings include
  max_worker_processes=0, the known versions of this attack are infeasible. However, undiscovered
  variants of the attack may be independent of that setting.");

  script_tag(name:"affected", value:"PostgreSQL 11.0 through 11.12, 12.0 through 12.7 and 13.0
  through 13.3.");

  script_tag(name:"solution", value:"Update to version 11.13, 12.8, 13.4 or later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2021-3677/");

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

if (version_in_range(version: version, test_version: "11.0", test_version2: "11.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "12.0", test_version2: "12.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "13.0", test_version2: "13.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);