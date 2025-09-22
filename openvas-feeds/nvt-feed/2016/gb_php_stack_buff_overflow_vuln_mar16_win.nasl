# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807092");
  script_version("2025-05-09T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-05-09 05:40:06 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2016-03-01 16:56:54 +0530 (Tue, 01 Mar 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_cve_id("CVE-2015-5589", "CVE-2015-5590", "CVE-2015-8838");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.4.43, 5.5.x < 5.5.27, 5.6.x < 5.6.11 Multiple Vulnerabilities (Mar 2016) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Inadequate boundary checks on user-supplied input by 'phar_fix_filepath' function in
  'ext/phar/phar.c' script.

  - Improper validation of file pointer in the 'phar_convert_to_other' function in
  'ext/phar/phar_object.c' script.");

  script_tag(name:"impact", value:"Successfully exploiting these issues allow remote attackers to
  execute arbitrary code in the context of the PHP process. Failed exploit attempts will likely
  crash the webserver.");

  script_tag(name:"affected", value:"PHP prior to version 5.4.43, 5.5.x prior to 5.5.27 and 5.6.x
  prior to 5.6.11 on Windows.");

  script_tag(name:"solution", value:"Update to version 5.4.43, 5.5.27, 5.6.11 or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75970");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/88763");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75974");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=69923");

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

if (version_is_less(version: version, test_version: "5.4.43")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.43", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.5.0", test_version_up: "5.5.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.27", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.6.0", test_version_up: "5.6.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
