# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142532");
  script_version("2024-07-19T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-07-19 05:05:32 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2019-07-02 04:59:03 +0000 (Tue, 02 Jul 2019)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-02 14:34:00 +0000 (Fri, 02 Oct 2020)");

  script_cve_id("CVE-2019-10164");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL 10.x < 10.9, 11.x < 11.4 Buffer Overflow Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_postgresql_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PostgreSQL is prone to a stack-based buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Any authenticated user can overflow a stack-based buffer by changing the user's
  own password to a purpose-crafted value. This often suffices to execute arbitrary code as the PostgreSQL
  operating system account.");

  script_tag(name:"affected", value:"PostgreSQL version 10.x prior to 10.9 and 11.x prior to 11.4.");

  script_tag(name:"solution", value:"Update to version 10.9, 11.4 or later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1949/");

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

if (version_in_range(version: version, test_version: "10.0", test_version2: "10.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0", test_version2: "11.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
