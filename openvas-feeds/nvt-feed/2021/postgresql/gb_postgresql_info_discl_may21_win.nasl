# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146880");
  script_version("2024-07-19T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-07-19 05:05:32 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2021-10-11 11:31:12 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-15 17:44:00 +0000 (Fri, 15 Oct 2021)");

  script_cve_id("CVE-2021-32029");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL 11.x < 11.12, 12.x < 12.7, 13.x < 13.3 Information Disclosure Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_postgresql_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PostgreSQL is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Using an UPDATE ... RETURNING on a purpose-crafted partitioned
  table, an attacker can read arbitrary bytes of server memory. In the default configuration, any
  authenticated database user can create prerequisite objects and complete this attack at will. A
  user lacking the CREATE and TEMPORARY privileges on all databases and the CREATE privilege on all
  schemas typically cannot use this attack at will.");

  script_tag(name:"affected", value:"PostgreSQL version 11.0 through 11.11, 12.0 through 12.6 and
  13.0 through 13.2.");

  script_tag(name:"solution", value:"Update to version 11.12, 12.7, 13.3 or later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2021-32029/");

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

if (version_in_range(version: version, test_version: "11.0", test_version2: "11.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "12.0", test_version2: "12.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "13.0", test_version2: "13.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
