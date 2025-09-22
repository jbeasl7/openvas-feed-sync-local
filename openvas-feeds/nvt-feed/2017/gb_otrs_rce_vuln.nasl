# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112139");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2017-11-24 08:52:38 +0100 (Fri, 24 Nov 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-08 18:57:00 +0000 (Wed, 08 May 2019)");

  script_cve_id("CVE-2017-16664");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_otrs_http_detect.nasl");
  script_mandatory_keys("otrs/detected");

  script_tag(name:"summary", value:"OTRS is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker who is logged into OTRS as an agent can request
  special URLs from OTRS which can lead to the execution of shell commands with the permissions of
  the web server user.");

  script_tag(name:"affected", value:"OTRS version 3.3.x through 3.3.19, 4.0.x through 4.0.25 and
  5.0.x through 5.0.23.");

  script_tag(name:"solution", value:"Update to version 3.3.20, 4.0.26, 5.0.24 or later.");

  script_xref(name:"URL", value:"https://www.otrs.com/security-advisory-2017-07-security-update-otrs-framework/");

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

if (version_in_range(version: version, test_version: "3.3.0", test_version2: "3.3.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.0.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.26", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
