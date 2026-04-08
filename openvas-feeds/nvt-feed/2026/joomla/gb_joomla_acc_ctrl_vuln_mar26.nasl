# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.156685");
  script_version("2026-04-07T07:51:48+0000");
  script_tag(name:"last_modification", value:"2026-04-07 07:51:48 +0000 (Tue, 07 Apr 2026)");
  script_tag(name:"creation_date", value:"2026-04-02 02:18:53 +0000 (Thu, 02 Apr 2026)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2026-21629");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! Access Control Vulnerability (20260301)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to an access control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The ajax component was excluded from the default logged-in-user
  check in the administrative area. This behavior was potentially unexpected by 3rd party
  developers.");

  script_tag(name:"affected", value:"Joomla! version 3.0.0 through 5.4.3 and 6.0.0 through
  6.0.3.");

  script_tag(name:"solution", value:"Update to version 5.4.4, 6.0.4 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/1027-20260301-core-acl-hardening-in-com-ajax.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "5.4.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
