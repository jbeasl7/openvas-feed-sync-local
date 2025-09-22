# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805686");
  script_version("2025-05-21T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-21 05:40:19 +0000 (Wed, 21 May 2025)");
  script_tag(name:"creation_date", value:"2015-07-23 13:10:57 +0530 (Thu, 23 Jul 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2015-2301");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.4.x < 5.4.40, 5.5.x < 5.5.22, 5.6.x < 5.6.6 RCE Vulnerability (Jul 2015) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to Use-after-free vulnerability in the
  'phar_rename_archive' function in 'phar_object.c' script");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow remote attackers to
  execute arbitrary code on the target system.");

  script_tag(name:"affected", value:"PHP versions 5.4.x prior to 5.4.40, 5.5.x prior to 5.5.22 and
  5.6.x prior to 5.6.6.");

  script_tag(name:"solution", value:"Update to version 5.4.40, 5.5.22, 5.6.6 or later.");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73037");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1194747");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-updates/2015-04/msg00002.html");

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

if (version_in_range_exclusive(version: version, test_version_lo: "5.4.0", test_version_up: "5.4.40")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.40", install_path: location);
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
