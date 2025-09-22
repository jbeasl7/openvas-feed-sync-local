# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812072");
  script_version("2025-05-09T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-05-09 05:40:06 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2017-11-09 18:44:32 +0530 (Thu, 09 Nov 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-19 11:15:00 +0000 (Mon, 19 Aug 2019)");

  script_cve_id("CVE-2017-16642");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.6.32, 7.x < 7.0.24, 7.1.x < 7.1.11 Heap Based Buffer Overflow Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to a heap buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the date extension's
  'timelib_meridian' handling of 'front of' and 'back of' directives.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow attacker to execute
  arbitrary code with elevated privileges within the context of a privileged process.");

  script_tag(name:"affected", value:"PHP prior to version 5.6.32, 7.x prior to 7.0.25 and 7.1.x
  prior to 7.1.11.");

  script_tag(name:"solution", value:"Update to version 5.6.32, 7.0.25, 7.1.11 or later.");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101745");
  script_xref(name:"URL", value:"http://php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=75055");

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

if (version_is_less(version: version, test_version: "5.6.32")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.0.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.1.0", test_version_up: "7.1.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
