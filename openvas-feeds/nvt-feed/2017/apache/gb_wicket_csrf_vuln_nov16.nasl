# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:wicket";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112077");
  script_version("2025-04-01T05:39:41+0000");
  script_tag(name:"last_modification", value:"2025-04-01 05:39:41 +0000 (Tue, 01 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-10-10 15:26:12 +0200 (Tue, 10 Oct 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-23 12:27:00 +0000 (Mon, 23 Oct 2017)");

  script_cve_id("CVE-2016-6806");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Wicket CSRF Detection Vulnerability (Nov 2016)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_wicket_consolidation.nasl");
  script_mandatory_keys("apache/wicket/detected");

  script_tag(name:"summary", value:"Apache Wicket is prone to a vulnerability affecting the
  cross-site request forgery (CSRF) detection.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Affected versions of Apache Wicket provide a CSRF prevention
  measure that fails to discover some cross origin requests.");

  script_tag(name:"affected", value:"Apache Wicket versions 6.20.0, 6.21.0, 6.22.0, 6.23.0,
  6.24.0, 7.0.0, 7.1.0, 7.2.0, 7.3.0, 7.4.0 and 8.0.0-M1.");

  script_tag(name:"solution", value:"Update to version 6.25.0, 7.5.0, 8.0.0-M2 or later.");

  script_xref(name:"URL", value:"https://wicket.apache.org/news/2016/11/08/cve-2016-6806.html");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/5dt69zpp5lsqrww8y52r287zy0pxjlgd");

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

if (version_in_range_exclusive(version: version, test_version_lo: "6.20.0", test_version_up: "6.25.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.25.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.5.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0.0-M1", test_version_up: "8.0.0-M2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0-M2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
