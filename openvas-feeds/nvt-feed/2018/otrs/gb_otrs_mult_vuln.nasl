# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112389");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2018-10-01 12:12:22 +0200 (Mon, 01 Oct 2018)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-21 17:55:00 +0000 (Wed, 21 Nov 2018)");

  script_cve_id("CVE-2018-16586", "CVE-2018-16587");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS 4.x < 4.0.32, 5.x < 5.0.30, 6.x < 6.0.11 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_otrs_http_detect.nasl");
  script_mandatory_keys("otrs/detected");

  script_tag(name:"summary", value:"OTRS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The following flaws exist:

  - CVE-2018-16586: When a logged in user opens a malicious email, the email could cause the browser
  to load external image or CSS resources.

  - CVE-2018-16587: When a user with admin permissions opens a malicious email, this may cause
  deletions of arbitrary files that the OTRS web server user has write access to.");

  script_tag(name:"affected", value:"OTRS version 4.x through 4.0.31, 5.x through 5.0.29 and 6.x
  through 6.0.10.");

  script_tag(name:"solution", value:"Update to version 4.0.32, 5.0.30, 6.0.11 or later.");

  script_xref(name:"URL", value:"https://community.otrs.com/security-advisory-2018-04-security-update-for-otrs-framework/");
  script_xref(name:"URL", value:"https://community.otrs.com/security-advisory-2018-05-security-update-for-otrs-framework/");

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

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.0.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
