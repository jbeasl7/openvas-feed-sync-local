# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152584");
  script_version("2024-07-22T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-10 04:29:10 +0000 (Wed, 10 Jul 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-19 18:53:34 +0000 (Fri, 19 Jul 2024)");

  script_cve_id("CVE-2024-26279");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! XSS Vulnerability (20240705)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Custom Fields component does not correctly filter inputs,
  leading to a XSS vector.");

  script_tag(name:"affected", value:"Joomla! version 3.7.0 through 3.10.15, 4.0.0 through 4.4.5 and
  5.0.0 through 5.1.1.");

  script_tag(name:"solution", value:"Update to version 3.10.16, 4.4.6, 5.1.2 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/939-20240705-core-xss-in-com-fields-default-field-value.html");

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

if (version_in_range(version: version, test_version: "3.7.0", test_version2: "3.10.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.10.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.4.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
