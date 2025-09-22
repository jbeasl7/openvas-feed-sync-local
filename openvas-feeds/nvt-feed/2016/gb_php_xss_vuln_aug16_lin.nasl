# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809137");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-08-17 15:28:57 +0530 (Wed, 17 Aug 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_cve_id("CVE-2015-8935");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.4.38, 5.5.x < 5.5.22, 5.6.x < 5.6.6 XSS Vulnerability (Aug 2016) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the 'sapi_header_op' function in
  'main/SAPI.c' script supports deprecated line folding without considering browser
  compatibility.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows remote attackers to
  conduct cross-site scripting (XSS) attacks against Internet Explorer by leveraging '%0A%20' or
  '%0D%0A%20' mishandling in the header function.");

  script_tag(name:"affected", value:"PHP prior to version 5.4.38, 5.5.x prior to 5.5.22 and 5.6.x
  prior to 5.6.6 on Linux.");

  script_tag(name:"solution", value:"Update to version 5.4.38, 5.5.22, 5.6.6 or later.");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=68978");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92356");

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

if (version_is_less(version: version, test_version: "5.4.38")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.38", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.5.0", test_version_up: "5.5.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.6.0", test_version_up: "5.6.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
