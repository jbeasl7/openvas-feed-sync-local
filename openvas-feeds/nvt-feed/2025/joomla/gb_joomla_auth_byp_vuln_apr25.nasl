# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128117");
  script_version("2025-05-09T15:42:11+0000");
  script_tag(name:"last_modification", value:"2025-05-09 15:42:11 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2025-04-14 10:53:07 +0000 (Mon, 14 Apr 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2025-25227");

  script_name("Joomla! Authentication Bypass Vulnerability (20250402)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Insufficient state checks leads to a vector that allows to
  bypass 2FA checks.");

  script_tag(name:"affected", value:"Joomla! version 4.0.0 through 4.4.12 and 5.0.0 through
  5.2.5.");

  script_tag(name:"solution", value:"Update to version 4.4.13, 5.2.6 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/964-20250402-core-mfa-authentication-bypass.html");

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

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.4.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
