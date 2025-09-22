# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106367");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-11-02 09:37:45 +0700 (Wed, 02 Nov 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-18 02:59:00 +0000 (Sat, 18 Feb 2017)");

  script_cve_id("CVE-2016-9139");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS < 3.3.16, 4.x <= 4.0.18, 5.x <= 5.0.13 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_otrs_http_detect.nasl");
  script_mandatory_keys("otrs/detected");

  script_tag(name:"summary", value:"OTRS is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker could trick an authenticated agent or customer into
  opening a malicious attachment which could lead to the execution of JavaScript in OTRS context.");

  script_tag(name:"affected", value:"OTRS prior to version 3.3.16, 4.x through 4.0.18 and 5.x
  through 5.0.13.");

  script_tag(name:"solution", value:"Update to version 3.3.16, 4.0.19, 5.0.14 or later.");

  script_xref(name:"URL", value:"https://www.otrs.com/security-advisory-2016-02-security-update-otrs/");

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

if (version_is_less(version: version, test_version: "3.3.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.0.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
