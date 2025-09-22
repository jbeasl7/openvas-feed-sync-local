# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151798");
  script_version("2024-02-23T14:36:45+0000");
  script_tag(name:"last_modification", value:"2024-02-23 14:36:45 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-23 03:16:42 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2024-21723");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! Open Redirect Vulnerability (20240202)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to an open redirect vulnerability in the
  installation application.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Inadequate parsing of URLs could result into an open
  redirect.");

  script_tag(name:"affected", value:"Joomla! version 1.5.0 through 3.10.14, 4.0.0 through 4.4.2 and
  5.0.0 through 5.0.2.");

  script_tag(name:"solution", value:"Update to version 3.10.15, 4.4.3, 5.0.3 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/926-20240202-core-open-redirect-in-installation-application.html");

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

if (version_in_range(version: version, test_version: "1.5.0", test_version2: "3.10.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.10.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
