# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.133159");
  script_version("2026-01-13T05:47:36+0000");
  script_tag(name:"last_modification", value:"2026-01-13 05:47:36 +0000 (Tue, 13 Jan 2026)");
  script_tag(name:"creation_date", value:"2026-01-07 09:10:41 +0000 (Wed, 07 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-07 15:35:12 +0000 (Wed, 07 Jan 2026)");

  script_cve_id("CVE-2025-68951");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyFAQ XSS Vulnerability (GHSA-jv8r-hv7q-p6vc)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyfaq_http_detect.nasl");
  script_mandatory_keys("phpmyfaq/detected");

  script_tag(name:"summary", value:"phpMyFAQ is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Allows an attacker to execute arbitrary JavaScript in an
  administrator?s browser by registering a user whose display name contains HTML entities (e.g.,
  &lt,img ...&gt,). When an administrator views the admin user list, the payload is decoded
  server-side and rendered without escaping, resulting in script execution in the admin context.");

  script_tag(name:"impact", value:"Successful exploitation can lead to admin session compromise
  (depending on cookie flags), CSRF token exfiltration and privileged admin actions, and UI
  redress/phishing within the admin panel.");

  script_tag(name:"affected", value:"phpMyFAQ versions starting from 4.0.14 and prior to 4.0.16 and
  4.1.0-RC only.");

  script_tag(name:"solution", value:"Update to version 4.0.16, 4.1.0 final or later.");

  script_xref(name:"URL", value:"https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-jv8r-hv7q-p6vc");

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

if (version_in_range_exclusive(version: version, test_version_lo: "4.0.14", test_version_up: "4.0.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.16",
                            install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.1.0-rc")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.0 final",
                            install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
