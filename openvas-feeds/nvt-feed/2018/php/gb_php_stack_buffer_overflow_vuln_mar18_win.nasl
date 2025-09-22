# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812820");
  script_version("2025-05-09T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-05-09 05:40:06 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2018-03-09 15:58:06 +0530 (Fri, 09 Mar 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-19 11:15:00 +0000 (Mon, 19 Aug 2019)");

  script_cve_id("CVE-2018-7584");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.x < 5.6.34, 7.x < 7.0.28, 7.1.x < 7.1.15, 7.2.x < 7.2.3 Stack Buffer Overflow Vulnerability (Mar 2018) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to a stack buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because php fails to adequately bounds-check
  user-supplied data before copying it into an insufficiently sized buffer.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to execute
  arbitrary code in the context of the affected application. Failed exploit attempts will result in
  denial-of-service conditions.");

  script_tag(name:"affected", value:"PHP versions 5.x prior to 5.6.34, 7.x prior to 7.0.28, 7.1.x
  prior to 7.1.15 and 7.2.x prior to 7.2.3 on Windows.");

  script_tag(name:"solution", value:"Update to version 5.6.34, 7.0.28, 7.1.15, 7.2.3 or later.");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103204");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=75981");

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

if (version_in_range_exclusive(version: version, test_version_lo: "5.0.0", test_version_up: "5.6.34")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.34", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.0.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.28", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.1.0", test_version_up: "7.1.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.2.0", test_version_up: "7.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
