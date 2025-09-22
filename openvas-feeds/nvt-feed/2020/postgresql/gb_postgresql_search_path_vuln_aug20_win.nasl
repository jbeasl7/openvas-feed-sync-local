# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144708");
  script_version("2024-07-19T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-07-19 05:05:32 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2020-10-07 07:03:40 +0000 (Wed, 07 Oct 2020)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-18 12:15:00 +0000 (Fri, 18 Sep 2020)");

  script_cve_id("CVE-2020-14349");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL 10.x < 10.14, 11.x < 11.9, 12.x < 12.4 Search Path Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_postgresql_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PostgreSQL is prone to an uncontrolled search path element vulnerability in
  logical replication.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The PostgreSQL search_path setting determines schemas searched for tables,
  functions, operators, etc. The CVE-2018-1058 fix caused most PostgreSQL-provided client applications to sanitize
  search_path, but logical replication continued to leave search_path unchanged. Users of a replication publisher
  or subscriber database can create objects in the public schema and harness them to execute arbitrary SQL
  functions under the identity running replication, often a superuser. Installations having adopted a documented
  secure schema usage pattern are not vulnerable.");

  script_tag(name:"affected", value:"PostgreSQL versions 10.x prior to 10.14, 11.x prior to 11.9 and 12.x
  prior to 12.4.");

  script_tag(name:"solution", value:"Update to version 10.14, 11.9, 12.4 or later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/postgresql-124-119-1014-9619-9523-and-13-beta-3-released-2060/");

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

if (version_in_range(version: version, test_version: "10.0", test_version2: "10.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0", test_version2: "11.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "12.0", test_version2: "12.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
