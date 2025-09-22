# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143584");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2020-03-06 03:04:26 +0000 (Fri, 06 Mar 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_cve_id("CVE-2020-9402");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django 1.11.x < 1.11.29, 2.2.x < 2.2.11, 3.0.x < 3.0.4 SQL Injection Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_django_detect_lin.nasl");
  script_mandatory_keys("Django/Linux/Ver");

  script_tag(name:"summary", value:"Django is prone to an SQL injection vulnerability.");

  script_tag(name:"insight", value:"Django allows SQL Injection if untrusted data is used as a tolerance parameter
  in GIS functions and aggregates on Oracle. By passing a suitably crafted tolerance to GIS functions and
  aggregates on Oracle, it was possible to break escaping and inject malicious SQL.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Django versions 1.11.x, 2.2.x and 3.0.x.");

  script_tag(name:"solution", value:"Update to version 1.11.29, 2.2.11, 3.0.4 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2020/mar/04/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "1.11.0", test_version2: "1.11.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.11.29", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.2.0", test_version2: "2.2.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.11", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "3.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.4", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
