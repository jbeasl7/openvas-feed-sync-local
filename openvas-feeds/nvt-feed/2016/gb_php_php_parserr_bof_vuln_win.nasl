# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809742");
  script_version("2025-05-09T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-05-09 05:40:06 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2016-12-05 17:06:26 +0530 (Mon, 05 Dec 2016)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-4049");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.3.x < 5.3.29, 5.4.x < 5.4.30, 5.5.x < 5.5.14, 5.6.0alpha1 < 5.6.0 Heap Based Buffer Overflow Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to a heap-based buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to buffer overflow error in the 'php_parserr'
  function in ext/standard/dns.c script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows remote attackers to
  cause a denial of service (crash) and possibly execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"PHP versions 5.3.x prior to 5.3.29, 5.4.x prior to 5.4.30,
  5.5.x prior to 5.5.14 and 5.6.x prior to 5.6.0 on Windows.");

  script_tag(name:"solution", value:"Update to version 5.3.29, 5.4.30, 5.5.14, 5.6.0 or later.");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68007");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2014/06/13/4");

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

if (version_in_range_exclusive(version: version, test_version_lo: "5.3.0", test_version_up: "5.3.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.4.0", test_version_up: "5.4.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.5.0", test_version_up: "5.5.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.6.0alpha1", test_version_up: "5.6.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
