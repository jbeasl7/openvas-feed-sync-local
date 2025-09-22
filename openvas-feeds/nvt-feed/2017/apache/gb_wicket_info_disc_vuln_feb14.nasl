# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:wicket";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112076");
  script_version("2025-04-01T05:39:41+0000");
  script_tag(name:"last_modification", value:"2025-04-01 05:39:41 +0000 (Tue, 01 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-10-10 15:13:12 +0200 (Tue, 10 Oct 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-11 17:32:00 +0000 (Wed, 11 Oct 2017)");

  script_cve_id("CVE-2014-0043");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Wicket Information Disclosure Vulnerability (Feb 2014)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_wicket_consolidation.nasl");
  script_mandatory_keys("apache/wicket/detected");

  script_tag(name:"summary", value:"Apache Wicket is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By issuing requests to special URLs handled by Wicket it is
  possible to check for the existence of particular classes in the classpath and thus check whether
  a third party library with a known security vulnerability is in use.");

  script_tag(name:"affected", value:"Apache Wicket versions 1.5.x prior to 1.5.11 and 6.x prior to
  6.14.0.");

  script_tag(name:"solution", value:"Update to version 1.5.11, 6.14.0 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/0k5v9bcfx2nsb3xdm03883qcd4pchjvm");
  script_xref(name:"URL", value:"https://wicket.apache.org/news/2014/02/21/cve-2014-0043.html");

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

if (version_in_range(version: version, test_version: "1.5.0", test_version2: "1.5.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0.0", test_version_up: "6.14.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.14.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
