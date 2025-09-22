# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:wicket";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144384");
  script_version("2025-04-01T05:39:41+0000");
  script_tag(name:"last_modification", value:"2025-04-01 05:39:41 +0000 (Tue, 01 Apr 2025)");
  script_tag(name:"creation_date", value:"2020-08-12 02:31:15 +0000 (Wed, 12 Aug 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-26 17:15:00 +0000 (Sat, 26 Jun 2021)");

  script_cve_id("CVE-2020-11976");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Wicket Information Disclosure Vulnerability (Aug 2020)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_wicket_consolidation.nasl");
  script_mandatory_keys("apache/wicket/detected");

  script_tag(name:"summary", value:"Apache Wicket is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By crafting a special URL it is possible to make Wicket
  deliver unprocessed HTML templates. This would allow an attacker to see possibly sensitive
  information inside a HTML template that is usually removed during rendering. For example if there
  are credentials in the markup which are never supposed to be visible to the client.");

  script_tag(name:"affected", value:"Apache Wicket versions 7.16.0, 8.8.0 and 9.0.0-M5.");

  script_tag(name:"solution", value:"Update to version 7.17.0, 8.9.0, 9.0.0 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/fcbd325lhg5fz7g7mvomc3wt33pjo996");

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

if (version_is_equal(version: version, test_version: "7.16.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.17.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "8.8.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.9.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "9.0.0.M5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
